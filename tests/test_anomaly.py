"""
tests/test_anomaly.py — Anomaly detection engine + AI analysis integration.

Coverage
────────
  Anomaly detection (all 4 categories):
  - brute_force  → type=brute_force, severity=HIGH
  - sql_injection → type=sql_injection, severity=CRITICAL
  - xss          → type=xss, severity=HIGH
  - auth_anomaly → type=auth_anomaly, severity=MEDIUM
  - Multi-type batch → all 4 types present
  - Clean batch   → anomaly_count=0, anomalies=[]

  AI analysis integration (sync endpoint):
  - CRITICAL/HIGH anomalies → ai_analysis is a dict
  - Clean batch → ai_analysis is None
  - AI analysis has required fields: mode, model, threat_level, attack_types, summary
  - Mock mode values are correct
"""

from __future__ import annotations

import json
import pytest

from tests.conftest import (
    VALID_KEY, make_logs,
    BRUTE_FORCE, SQL_INJECTION, XSS, AUTH_ANOMALY, MULTI_ANOMALY,
)


def post(client, logs, api_key=VALID_KEY):
    return client.post(
        "/v1/logs",
        content=json.dumps(logs).encode(),
        headers={"Content-Type": "application/json", "X-API-Key": api_key},
    )


# ---------------------------------------------------------------------------
# Anomaly detection — individual categories
# ---------------------------------------------------------------------------

class TestAnomalyDetection:
    def test_clean_batch_zero_anomalies(self, client):
        resp = post(client, make_logs(20))
        body = resp.json()
        assert body["anomaly_count"] == 0
        assert body["anomalies"] == []

    def test_brute_force_detected(self, client):
        resp = post(client, [BRUTE_FORCE])
        body = resp.json()
        assert body["anomaly_count"] > 0
        types = [a["type"] for a in body["anomalies"]]
        assert "brute_force" in types

    def test_brute_force_severity_is_high(self, client):
        resp = post(client, [BRUTE_FORCE])
        match = next(a for a in resp.json()["anomalies"] if a["type"] == "brute_force")
        assert match["severity"] == "HIGH"

    def test_sql_injection_detected(self, client):
        resp = post(client, [SQL_INJECTION])
        types = [a["type"] for a in resp.json()["anomalies"]]
        assert "sql_injection" in types

    def test_sql_injection_severity_is_critical(self, client):
        resp = post(client, [SQL_INJECTION])
        match = next(a for a in resp.json()["anomalies"] if a["type"] == "sql_injection")
        assert match["severity"] == "CRITICAL"

    def test_xss_detected(self, client):
        resp = post(client, [XSS])
        types = [a["type"] for a in resp.json()["anomalies"]]
        assert "xss" in types

    def test_xss_severity_is_high(self, client):
        resp = post(client, [XSS])
        match = next(a for a in resp.json()["anomalies"] if a["type"] == "xss")
        assert match["severity"] == "HIGH"

    def test_auth_anomaly_detected(self, client):
        resp = post(client, [AUTH_ANOMALY])
        types = [a["type"] for a in resp.json()["anomalies"]]
        assert "auth_anomaly" in types

    def test_auth_anomaly_severity_is_medium(self, client):
        resp = post(client, [AUTH_ANOMALY])
        match = next(a for a in resp.json()["anomalies"] if a["type"] == "auth_anomaly")
        assert match["severity"] == "MEDIUM"

    def test_multi_type_batch_all_types_present(self, client):
        resp = post(client, [MULTI_ANOMALY])
        found = {a["type"] for a in resp.json()["anomalies"]}
        expected = {"brute_force", "sql_injection", "xss", "auth_anomaly"}
        assert expected <= found, f"Missing types: {expected - found}"

    def test_anomaly_count_matches_anomalies_list_length(self, client):
        resp = post(client, [BRUTE_FORCE, SQL_INJECTION])
        body = resp.json()
        assert body["anomaly_count"] == len(body["anomalies"])

    def test_anomaly_has_type_field(self, client):
        resp = post(client, [BRUTE_FORCE])
        for a in resp.json()["anomalies"]:
            assert "type" in a

    def test_anomaly_has_severity_field(self, client):
        resp = post(client, [SQL_INJECTION])
        for a in resp.json()["anomalies"]:
            assert "severity" in a

    def test_meter_present_alongside_anomalies(self, client):
        """Anomalous logs are still metered."""
        resp = post(client, [SQL_INJECTION])
        assert resp.json()["meter_event_id"] is not None


# ---------------------------------------------------------------------------
# AI analysis — integration with sync /v1/logs endpoint
# ---------------------------------------------------------------------------

class TestAIAnalysisIntegration:
    def test_clean_batch_ai_analysis_is_none(self, client):
        resp = post(client, make_logs(10))
        assert resp.json()["ai_analysis"] is None

    def test_critical_anomaly_triggers_ai_analysis(self, client):
        resp = post(client, [SQL_INJECTION])
        ai = resp.json().get("ai_analysis")
        assert isinstance(ai, dict), f"Expected dict, got {ai!r}"

    def test_high_anomaly_triggers_ai_analysis(self, client):
        resp = post(client, [BRUTE_FORCE])
        ai = resp.json().get("ai_analysis")
        assert isinstance(ai, dict)

    def test_medium_only_anomaly_no_ai_analysis(self, client):
        """AUTH_ANOMALY is MEDIUM — should not trigger AI analysis."""
        resp = post(client, [AUTH_ANOMALY])
        ai = resp.json().get("ai_analysis")
        assert ai is None, f"Expected None for MEDIUM anomaly, got: {ai}"

    def test_ai_analysis_has_mode_field(self, client):
        resp = post(client, [SQL_INJECTION])
        ai = resp.json()["ai_analysis"]
        assert "mode" in ai
        assert ai["mode"] in ("live", "mock")

    def test_ai_analysis_has_model_field(self, client):
        resp = post(client, [BRUTE_FORCE])
        assert "model" in resp.json()["ai_analysis"]

    def test_ai_analysis_has_threat_level_field(self, client):
        resp = post(client, [SQL_INJECTION])
        ai = resp.json()["ai_analysis"]
        assert ai.get("threat_level") in ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    def test_ai_analysis_has_attack_types_list(self, client):
        resp = post(client, [BRUTE_FORCE])
        ai = resp.json()["ai_analysis"]
        assert isinstance(ai.get("attack_types"), list)
        assert len(ai["attack_types"]) > 0

    def test_ai_analysis_has_summary_string(self, client):
        resp = post(client, [SQL_INJECTION])
        ai = resp.json()["ai_analysis"]
        summary = ai.get("summary", "")
        assert isinstance(summary, str) and len(summary) > 20

    def test_mock_mode_has_disclaimer(self, client):
        """In mock mode (no real OPENAI_API_KEY), disclaimer field is present."""
        resp = post(client, [BRUTE_FORCE])
        ai = resp.json()["ai_analysis"]
        if ai.get("mode") == "mock":
            assert "disclaimer" in ai

    def test_ai_analysis_critical_threat_level_for_sql(self, client):
        resp = post(client, [SQL_INJECTION])
        ai = resp.json()["ai_analysis"]
        assert ai["threat_level"] == "CRITICAL"

    def test_ai_analysis_attack_type_matches_anomaly(self, client):
        resp = post(client, [BRUTE_FORCE])
        ai = resp.json()["ai_analysis"]
        assert "brute_force" in ai["attack_types"]
