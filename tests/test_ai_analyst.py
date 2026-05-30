"""
tests/test_ai_analyst.py — Unit tests for utils/ai_analyst.py.

Coverage
────────
  - analyze_anomalies returns None for empty list
  - analyze_anomalies returns None for MEDIUM/LOW only
  - analyze_anomalies returns dict for CRITICAL
  - analyze_anomalies returns dict for HIGH
  - Mock summary has all required fields
  - Mock summary: mode == "mock"
  - Mock brute_force template
  - Mock sql_injection template
  - Mock xss template
  - Mock auth_anomaly template
  - Mock multi-type summary
  - _top_severity helper
  - _source_ip extraction
  - Live fallback to mock on API error
"""

from __future__ import annotations

import pytest
from unittest.mock import patch, MagicMock

from utils.ai_analyst import analyze_anomalies, _mock_summary, _top_severity, _source_ip


# ---------------------------------------------------------------------------
# Fixtures — sample anomaly dicts
# ---------------------------------------------------------------------------

CRITICAL_ANOMALY = {"type": "sql_injection", "severity": "CRITICAL", "source_ip": "1.2.3.4"}
HIGH_ANOMALY     = {"type": "brute_force",   "severity": "HIGH",     "source_ip": "5.6.7.8"}
MEDIUM_ANOMALY   = {"type": "auth_anomaly",  "severity": "MEDIUM",   "source_ip": "9.10.11.12"}
LOW_ANOMALY      = {"type": "auth_anomaly",  "severity": "LOW",      "source_ip": "9.10.11.12"}


# ---------------------------------------------------------------------------
# analyze_anomalies — entry-point contract
# ---------------------------------------------------------------------------

class TestAnalyzeAnomalies:
    def test_empty_list_returns_none(self):
        assert analyze_anomalies([]) is None

    def test_medium_only_returns_none(self):
        assert analyze_anomalies([MEDIUM_ANOMALY]) is None

    def test_low_only_returns_none(self):
        assert analyze_anomalies([LOW_ANOMALY]) is None

    def test_critical_returns_dict(self):
        result = analyze_anomalies([CRITICAL_ANOMALY])
        assert isinstance(result, dict)

    def test_high_returns_dict(self):
        result = analyze_anomalies([HIGH_ANOMALY])
        assert isinstance(result, dict)

    def test_mixed_critical_and_medium_returns_dict(self):
        result = analyze_anomalies([CRITICAL_ANOMALY, MEDIUM_ANOMALY])
        assert isinstance(result, dict)

    def test_result_has_summary(self):
        result = analyze_anomalies([HIGH_ANOMALY])
        assert isinstance(result.get("summary"), str)
        assert len(result["summary"]) > 10

    def test_result_has_mode(self):
        result = analyze_anomalies([CRITICAL_ANOMALY])
        assert result.get("mode") in ("live", "mock")

    def test_result_has_model(self):
        result = analyze_anomalies([HIGH_ANOMALY])
        assert result.get("model") is not None

    def test_result_has_threat_level(self):
        result = analyze_anomalies([CRITICAL_ANOMALY])
        assert result.get("threat_level") in ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    def test_result_has_attack_types_list(self):
        result = analyze_anomalies([HIGH_ANOMALY])
        assert isinstance(result.get("attack_types"), list)


# ---------------------------------------------------------------------------
# _mock_summary — template correctness
# ---------------------------------------------------------------------------

class TestMockSummary:
    def test_mode_is_mock(self):
        result = _mock_summary([CRITICAL_ANOMALY])
        assert result["mode"] == "mock"

    def test_model_is_mock_analyst(self):
        result = _mock_summary([HIGH_ANOMALY])
        assert "mock" in result["model"].lower()

    def test_has_disclaimer(self):
        result = _mock_summary([CRITICAL_ANOMALY])
        assert "disclaimer" in result

    def test_disclaimer_mentions_openai_key(self):
        result = _mock_summary([HIGH_ANOMALY])
        assert "OPENAI_API_KEY" in result["disclaimer"]

    def test_brute_force_template(self):
        result = _mock_summary([HIGH_ANOMALY])
        summary = result["summary"].lower()
        assert "brute" in summary or "credential" in summary or "authentication" in summary

    def test_sql_injection_template(self):
        result = _mock_summary([CRITICAL_ANOMALY])
        summary = result["summary"].lower()
        assert "sql" in summary or "injection" in summary or "database" in summary

    def test_xss_template(self):
        xss = {"type": "xss", "severity": "HIGH", "source_ip": "1.2.3.4"}
        result = _mock_summary([xss])
        summary = result["summary"].lower()
        assert "xss" in summary or "cross-site" in summary or "script" in summary

    def test_auth_anomaly_template(self):
        result = _mock_summary([MEDIUM_ANOMALY])
        summary = result["summary"].lower()
        assert "privilege" in summary or "escalation" in summary or "authentication" in summary

    def test_multi_type_uses_multi_template(self):
        result = _mock_summary([HIGH_ANOMALY, CRITICAL_ANOMALY])
        attack_types = result["attack_types"]
        assert len(attack_types) >= 2

    def test_threat_level_highest_severity(self):
        result = _mock_summary([HIGH_ANOMALY, CRITICAL_ANOMALY])
        assert result["threat_level"] == "CRITICAL"

    def test_single_type_attack_types_list(self):
        result = _mock_summary([HIGH_ANOMALY])
        assert isinstance(result["attack_types"], list)
        assert len(result["attack_types"]) == 1


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

class TestHelpers:
    def test_top_severity_critical_wins(self):
        anomalies = [
            {"severity": "HIGH"},
            {"severity": "CRITICAL"},
            {"severity": "MEDIUM"},
        ]
        assert _top_severity(anomalies) == "CRITICAL"

    def test_top_severity_single(self):
        assert _top_severity([{"severity": "HIGH"}]) == "HIGH"

    def test_top_severity_fallback_to_low(self):
        assert _top_severity([{"severity": "LOW"}]) == "LOW"

    def test_source_ip_extracts_from_source_ip_key(self):
        ip = _source_ip([{"source_ip": "10.20.30.40"}])
        assert ip == "10.20.30.40"

    def test_source_ip_fallback_when_missing(self):
        ip = _source_ip([{"message": "no ip here"}])
        assert isinstance(ip, str)
        assert len(ip) > 0


# ---------------------------------------------------------------------------
# Live-mode fallback
# ---------------------------------------------------------------------------

class TestLiveFallback:
    def test_openai_error_falls_back_to_mock(self):
        """If the OpenAI API raises, the result should fall back to mock mode."""
        import utils.ai_analyst as module

        original_mode = module._MODE
        original_key  = module._OPENAI_KEY
        try:
            module._MODE       = "live"
            module._OPENAI_KEY = "sk-fake-key-for-error-testing"

            # _live_summary does `from openai import OpenAI` lazily inside the
            # function body.  Patching openai.OpenAI replaces the attribute on
            # the already-imported module, so the lazy import picks it up.
            with patch("openai.OpenAI", side_effect=Exception("Connection refused")):
                result = module._live_summary([CRITICAL_ANOMALY])

            assert result["mode"] == "mock"
            assert "fallback_reason" in result
        finally:
            module._MODE       = original_mode
            module._OPENAI_KEY = original_key
