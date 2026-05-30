"""
utils/ai_analyst.py — AI Security Analyst

Generates human-readable threat summaries for CRITICAL/HIGH anomalies.

Live mode  — uses gpt-4o-mini via the OpenAI API (requires OPENAI_API_KEY).
Mock mode  — uses deterministic, template-based summaries that are
             indistinguishable in structure from live responses.

The mode is selected at module import time:
  - OPENAI_API_KEY starts with "sk-"  → live
  - key missing, empty, or invalid    → mock

In live mode any API failure (network error, quota, invalid key) is caught
and automatically retried with mock so the product never surfaces a 500.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

log = logging.getLogger("synthegria.ai")

_OPENAI_KEY: str = os.environ.get("OPENAI_API_KEY", "")
_MODE: str = "live" if _OPENAI_KEY.startswith("sk-") else "mock"

# ---------------------------------------------------------------------------
# Prompt
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are an expert cybersecurity analyst embedded in the Synthegria SIEM platform.
Your role is to analyse structured security log anomalies and produce concise,
actionable threat summaries for first-responders and SOC analysts.

Rules:
- Plain English, 3-5 sentences maximum.
- State: threat type → attack vector → potential impact → immediate action.
- Use severity-appropriate urgency: CRITICAL = escalate now, HIGH = act today.
- Never invent data that is not present in the anomaly payload.
- Do not include JSON, bullet lists, or markdown headers — prose only.\
"""

# ---------------------------------------------------------------------------
# Mock templates
# ---------------------------------------------------------------------------

_MOCK: dict[str, str] = {
    "brute_force": (
        "A brute-force credential attack has been detected from {source_ip}, "
        "characterised by repeated failed authentication attempts against privileged accounts. "
        "The pattern is consistent with automated credential-stuffing or a dictionary attack "
        "and indicates an active attempt to gain unauthorised system access. "
        "Recommended action: block the source IP immediately, enforce account lockout "
        "thresholds, and enable MFA for all targeted accounts."
    ),
    "sql_injection": (
        "A SQL injection attack has been identified in inbound HTTP requests from {source_ip}, "
        "containing {signature} payloads designed to exfiltrate or manipulate the backend database. "
        "Successful exploitation could result in full database compromise, data exfiltration, "
        "or complete system takeover. "
        "Recommended action: block the source IP, migrate all queries to parameterised statements, "
        "and perform an immediate database integrity audit."
    ),
    "xss": (
        "A Cross-Site Scripting (XSS) attack has been detected from {source_ip}, "
        "with malicious scripts targeting session cookies embedded in application input fields. "
        "If executed in a victim's browser, this could lead to session hijacking and account takeover. "
        "Recommended action: deploy Content-Security-Policy headers, encode all user-supplied output "
        "server-side, and audit recent user sessions for signs of compromise."
    ),
    "auth_anomaly": (
        "An authentication anomaly consistent with privilege escalation has been detected from {source_ip}. "
        "Unauthorised elevation of access rights — including sudo execution and role modification — "
        "suggests a compromised privileged account or an insider threat actor. "
        "Recommended action: suspend the affected account immediately, audit recent privilege changes "
        "in your IAM system, and initiate a full access review."
    ),
    "multi": (
        "Multiple simultaneous attack vectors — including {types} — have been detected in this batch, "
        "originating from {source_ip}. "
        "This compound threat pattern is consistent with a coordinated APT campaign conducting "
        "reconnaissance and exploitation across multiple surfaces simultaneously. "
        "Recommended action: activate your incident response playbook, isolate affected network "
        "segments, and escalate to your security operations team immediately."
    ),
}

_SEVERITY_RANK: dict[str, int] = {
    "CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1,
}


def _top_severity(anomalies: list[dict[str, Any]]) -> str:
    return max(
        (a.get("severity", "LOW") for a in anomalies),
        key=lambda s: _SEVERITY_RANK.get(s, 0),
    )


def _source_ip(anomalies: list[dict[str, Any]]) -> str:
    for a in anomalies:
        for k, v in a.items():
            if isinstance(v, str) and ("ip" in k.lower() or "source" in k.lower()):
                return v
    return "an external host"


def _mock_summary(anomalies: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a deterministic, realistic-looking AI summary without API calls."""
    types = list({a.get("type", "unknown") for a in anomalies})
    ip    = _source_ip(anomalies)

    signatures = {
        "sql_injection": "UNION SELECT / DROP TABLE",
        "xss":           "<script> / document.cookie",
    }

    if len(types) > 1:
        summary = _MOCK.get("multi", "").format(
            types=", ".join(t.replace("_", " ") for t in types),
            source_ip=ip,
        )
    else:
        atype   = types[0] if types else "brute_force"
        tmpl    = _MOCK.get(atype, _MOCK["brute_force"])
        summary = tmpl.format(
            source_ip=ip,
            signature=signatures.get(atype, "malicious"),
        )

    return {
        "mode":        "mock",
        "model":       "synthegria-mock-analyst-v1",
        "threat_level": _top_severity(anomalies),
        "attack_types": types,
        "summary":     summary,
        "disclaimer":  (
            "AI analysis is running in mock mode. "
            "Set OPENAI_API_KEY to enable live gpt-4o-mini analysis."
        ),
    }


def _live_summary(anomalies: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Call gpt-4o-mini for a real threat summary.
    Gracefully falls back to mock on any API error.
    """
    try:
        from openai import OpenAI  # lazy import — not required in mock mode

        client = OpenAI(api_key=_OPENAI_KEY)
        payload_json = json.dumps(anomalies, indent=2)
        user_msg = (
            "Analyse the following SIEM anomalies and write a threat summary:\n\n"
            f"```json\n{payload_json}\n```"
        )

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system",  "content": _SYSTEM_PROMPT},
                {"role": "user",    "content": user_msg},
            ],
            max_tokens=300,
            temperature=0.2,
        )

        summary_text = response.choices[0].message.content.strip()
        types        = list({a.get("type", "unknown") for a in anomalies})

        log.info(
            "AI analyst (live)  types=%s  tokens=%s",
            types,
            response.usage.total_tokens if response.usage else "?",
        )

        return {
            "mode":         "live",
            "model":        "gpt-4o-mini",
            "threat_level": _top_severity(anomalies),
            "attack_types": types,
            "summary":      summary_text,
            "tokens_used":  response.usage.total_tokens if response.usage else None,
        }

    except Exception as exc:
        log.warning("OpenAI API unavailable, falling back to mock: %s", exc)
        result = _mock_summary(anomalies)
        result["fallback_reason"] = str(exc)
        return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_anomalies(anomalies: list[dict[str, Any]]) -> dict[str, Any] | None:
    """
    Generate an AI threat summary for CRITICAL/HIGH anomalies.

    Returns
    -------
    dict
        AI analysis envelope if any CRITICAL/HIGH anomalies are present.
    None
        When all anomalies are MEDIUM/LOW, or when anomalies is empty.
    """
    targets = [
        a for a in anomalies
        if a.get("severity") in ("CRITICAL", "HIGH")
    ]
    if not targets:
        return None

    log.info(
        "AI analyst: %d CRITICAL/HIGH anomaly(ies)  mode=%s",
        len(targets), _MODE,
    )
    return _live_summary(targets) if _MODE == "live" else _mock_summary(targets)
