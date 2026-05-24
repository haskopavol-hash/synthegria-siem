"""
utils/anomaly.py — Rules-based anomaly detection engine
=========================================================
Scans a batch of log-line dicts for common security signatures.

Rule categories
  brute_force   HIGH      Repeated auth failures, lockout patterns
  sql_injection CRITICAL  UNION SELECT, DROP TABLE, injection probes
  xss           HIGH      <script>, javascript:, event-handler injections
  auth_anomaly  MEDIUM    Privilege escalation, root login, sudo abuse

Usage
  from utils.anomaly import scan_logs
  result = scan_logs(log_batch)
  # result = {
  #   "anomaly_count": int,          # true total (may exceed len(anomalies))
  #   "anomalies": [                 # capped at MAX_ANOMALIES_RETURNED
  #     {
  #       "type":            str,    # rule category
  #       "severity":        str,    # CRITICAL | HIGH | MEDIUM | LOW
  #       "matched_pattern": str,    # human-readable description of the trigger
  #       "log":             dict,   # original log line (truncated if very large)
  #     },
  #     ...
  #   ],
  # }
"""

import re
from typing import Any

# Maximum number of anomaly details returned in a single response.
# The true count is always reported; this just caps the payload.
MAX_ANOMALIES_RETURNED = 100

# Maximum characters kept from a single log line's serialised text before
# pattern matching.  Prevents pathological O(n²) blowup on huge fields.
MAX_SCAN_CHARS = 4_096

# ---------------------------------------------------------------------------
# Rule definitions
# Each rule fires at most ONCE per log line (first matching pattern wins).
# ---------------------------------------------------------------------------

_RAW_RULES: list[dict] = [
    # ── Brute force ─────────────────────────────────────────────────────────
    {
        "type":     "brute_force",
        "severity": "HIGH",
        "patterns": [
            (r"failed[\s_\-]{0,10}(password|login|auth)",
             "failed auth keyword"),
            (r"authentication[\s_\-]{0,10}fail(ure|ed)?",
             "authentication failure"),
            (r"invalid[\s_\-]{0,10}(credential|password|user)",
             "invalid credentials"),
            (r"login[\s_\-]{0,10}(fail|attempt|denied)",
             "login failure/attempt"),
            (r"too[\s_\-]{0,10}many[\s_\-]{0,10}(attempt|request|login|fail)",
             "too many attempts"),
            (r"account[\s_\-]{0,10}lock(ed|out)?",
             "account lockout"),
            (r"\bbrute[\s_\-]{0,10}force\b",
             "brute-force keyword"),
            (r'"(status|status_code)"[\s:\"\']+["\']?(401|403)["\']?',
             "HTTP 401/403 status in log value"),
            (r"\b(401|403)\b.*\b(fail|deny|denied|unauthorized)\b",
             "401/403 with deny keyword"),
            (r"max(imum)?[\s_\-]{0,10}(retry|retries|attempt)",
             "max retry/attempt"),
        ],
    },
    # ── SQL injection ────────────────────────────────────────────────────────
    {
        "type":     "sql_injection",
        "severity": "CRITICAL",
        "patterns": [
            (r"\bunion[\s\+%0a\|]+select\b",
             "UNION SELECT"),
            (r"\bdrop[\s\+%0a]+table\b",
             "DROP TABLE"),
            (r"\bor[\s\+%0a]+1[\s]*=[\s]*1\b",
             "OR 1=1"),
            (r"'[\s]*or[\s]+'[\w]+'[\s]*=[\s]*'[\w]+",
             "OR '' = '' tautology"),
            (r";\s*(select|insert|update|delete|drop|truncate|alter)\b",
             "stacked query"),
            (r"\bexec\s*\(",
             "EXEC("),
            (r"\bxp_\w+",
             "extended stored procedure (xp_)"),
            (r"/\*[\s\S]{0,200}\*/",
             "SQL block comment"),
            (r"--[\s]*$",
             "SQL line comment at end"),
            (r"\bsleep\s*\(\s*\d+\s*\)",
             "time-based blind injection (SLEEP)"),
            (r"\bwaitfor[\s]+delay\b",
             "time-based blind injection (WAITFOR DELAY)"),
            (r"(char|nchar|varchar)\s*\(\s*\d",
             "CHAR() encoding"),
            (r"\bcast\s*\(.*\bas\b",
             "CAST() injection"),
            (r"\bconvert\s*\(.*,\s*(select|char|0x)",
             "CONVERT() injection"),
            (r"0x[0-9a-f]{4,}",
             "hex-encoded payload"),
        ],
    },
    # ── XSS ─────────────────────────────────────────────────────────────────
    {
        "type":     "xss",
        "severity": "HIGH",
        "patterns": [
            (r"<\s*script[\s>/]",
             "<script> tag"),
            (r"<\s*/\s*script\s*>",
             "</script> tag"),
            (r"javascript\s*:",
             "javascript: URI scheme"),
            (r"on(error|load|click|mouseover|focus|blur|submit|change|input)"
             r"\s*=\s*[\"'`]",
             "inline event handler (on*)"),
            (r"\balert\s*\(",
             "alert()"),
            (r"document\s*\.\s*cookie",
             "document.cookie"),
            (r"<\s*iframe[\s>/]",
             "<iframe> tag"),
            (r"\beval\s*\(",
             "eval()"),
            (r"&#x?[0-9a-f]{2,5};",
             "HTML/XML character entity encoding"),
            (r"%3c\s*script",
             "URL-encoded <script>"),
            (r"(src|href)\s*=\s*[\"']?\s*javascript\s*:",
             "javascript: in src/href"),
            (r"<\s*(img|svg|body|input|video|audio)[^>]{0,200}"
             r"on\w+\s*=",
             "event handler on media/input tag"),
            (r"expression\s*\(",
             "CSS expression()"),
            (r"vbscript\s*:",
             "vbscript: URI scheme"),
        ],
    },
    # ── Auth anomaly ─────────────────────────────────────────────────────────
    {
        "type":     "auth_anomaly",
        "severity": "MEDIUM",
        "patterns": [
            (r"privilege[\s_\-]{0,10}escalat",
             "privilege escalation"),
            (r"\bsudo\b",
             "sudo command"),
            (r"\bunauthorized\b",
             "unauthorized access"),
            (r"permission[\s_\-]{0,10}denied",
             "permission denied"),
            (r"access[\s_\-]{0,10}denied",
             "access denied"),
            (r"root[\s_\-]{0,10}login",
             "root login"),
            (r"\bsu\s+root\b",
             "su to root"),
            (r"token[\s_\-]{0,10}(expired|invalid|revoked|tampered)",
             "token issue"),
            (r"session[\s_\-]{0,10}(hijack|fixat|replay|forger)",
             "session attack"),
            (r"impersonat",
             "impersonation"),
            (r"jwt[\s_\-]{0,10}(invalid|tampered|expired|none)",
             "JWT issue"),
            (r"credential[\s_\-]{0,10}(stuff|harvest|dump|leak)",
             "credential stuffing/harvesting"),
        ],
    },
]

# ---------------------------------------------------------------------------
# Compile all patterns once at module load
# ---------------------------------------------------------------------------

RULES: list[dict] = []
for _rule in _RAW_RULES:
    RULES.append({
        "type":     _rule["type"],
        "severity": _rule["severity"],
        "patterns": [
            (re.compile(pat, re.IGNORECASE | re.DOTALL), label)
            for pat, label in _rule["patterns"]
        ],
    })


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def _log_to_text(entry: dict) -> str:
    """
    Flatten all string values in a log dict to a single scannable string.
    Non-string values are converted via str().  Truncated to MAX_SCAN_CHARS.
    """
    parts: list[str] = []
    for val in entry.values():
        if isinstance(val, str):
            parts.append(val)
        elif isinstance(val, (int, float, bool)):
            parts.append(str(val))
        elif isinstance(val, (list, dict)):
            try:
                parts.append(str(val))
            except Exception:
                pass
    return " ".join(parts)[:MAX_SCAN_CHARS]


def _truncate_log(entry: dict, max_chars: int = 500) -> dict:
    """
    Return a copy of *entry* with long string values truncated, so anomaly
    payloads don't bloat the API response.
    """
    out: dict[str, Any] = {}
    for k, v in entry.items():
        if isinstance(v, str) and len(v) > max_chars:
            out[k] = v[:max_chars] + "…"
        else:
            out[k] = v
    return out


def scan_logs(logs: list[dict]) -> dict:
    """
    Scan *logs* for security anomalies.

    Returns::

        {
            "anomaly_count": int,          # true total detections
            "anomalies": [                 # up to MAX_ANOMALIES_RETURNED
                {
                    "type":            str,
                    "severity":        str,
                    "matched_pattern": str,
                    "log":             dict,
                },
                ...
            ]
        }

    A single log line can trigger multiple rules (one match per rule category
    per line — the first matching pattern in each rule wins).
    """
    found: list[dict] = []

    for entry in logs:
        if not isinstance(entry, dict):
            continue
        text = _log_to_text(entry)
        for rule in RULES:
            for regex, label in rule["patterns"]:
                if regex.search(text):
                    found.append({
                        "type":            rule["type"],
                        "severity":        rule["severity"],
                        "matched_pattern": label,
                        "log":             _truncate_log(entry),
                    })
                    break   # one match per rule per log line

    return {
        "anomaly_count": len(found),
        "anomalies":     found[:MAX_ANOMALIES_RETURNED],
    }
