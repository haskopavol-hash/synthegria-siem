"""
tests/test_ingestion.py — POST /v1/logs synchronous ingestion.

Coverage
────────
  - 200 response structure for valid batches
  - Empty batch (0 lines): no meter event
  - lines_received reflects actual payload length
  - meter_event_id present for non-empty batches
  - anomaly_count and anomalies[] always present
  - Non-array body → 422
  - Rate limit → 429 with Retry-After header
"""

from __future__ import annotations

import json
import pytest

from tests.conftest import VALID_KEY, VALID_KEY2, FAKE_METER_ID, make_logs


def post_logs(client, logs, api_key=VALID_KEY):
    return client.post(
        "/v1/logs",
        content=json.dumps(logs).encode(),
        headers={"Content-Type": "application/json", "X-API-Key": api_key},
    )


# ---------------------------------------------------------------------------
# Happy-path response structure
# ---------------------------------------------------------------------------

class TestIngestResponseStructure:
    def test_valid_batch_returns_200(self, client):
        resp = post_logs(client, make_logs(5))
        assert resp.status_code == 200

    def test_response_has_status_ok(self, client):
        resp = post_logs(client, make_logs(3))
        assert resp.json()["status"] == "ok"

    def test_response_lines_received_matches_payload(self, client):
        n = 7
        resp = post_logs(client, make_logs(n))
        assert resp.json()["lines_received"] == n

    def test_response_has_meter_event_id_for_nonempty_batch(self, client):
        resp = post_logs(client, make_logs(2))
        assert resp.json()["meter_event_id"] == FAKE_METER_ID

    def test_response_has_anomaly_count(self, client):
        resp = post_logs(client, make_logs(4))
        assert "anomaly_count" in resp.json()

    def test_response_has_anomalies_array(self, client):
        resp = post_logs(client, make_logs(4))
        assert isinstance(resp.json().get("anomalies"), list)

    def test_response_has_customer_id(self, client):
        resp = post_logs(client, make_logs(1))
        assert resp.json().get("customer_id") is not None

    def test_response_ai_analysis_field_present(self, client):
        """ai_analysis key must always be present (None or dict)."""
        resp = post_logs(client, make_logs(3))
        assert "ai_analysis" in resp.json()


# ---------------------------------------------------------------------------
# Empty batch
# ---------------------------------------------------------------------------

class TestEmptyBatch:
    def test_empty_batch_returns_200(self, client):
        resp = post_logs(client, [])
        assert resp.status_code == 200

    def test_empty_batch_lines_received_is_zero(self, client):
        resp = post_logs(client, [])
        assert resp.json()["lines_received"] == 0

    def test_empty_batch_no_meter_event(self, client):
        resp = post_logs(client, [])
        assert resp.json()["meter_event_id"] is None

    def test_empty_batch_zero_anomalies(self, client):
        resp = post_logs(client, [])
        assert resp.json()["anomaly_count"] == 0
        assert resp.json()["anomalies"] == []

    def test_empty_batch_has_message_field(self, client):
        resp = post_logs(client, [])
        assert "message" in resp.json()

    def test_empty_batch_no_ai_analysis(self, client):
        resp = post_logs(client, [])
        assert resp.json()["ai_analysis"] is None


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------

class TestIngestErrors:
    def test_non_array_body_returns_422(self, client):
        resp = client.post(
            "/v1/logs",
            content=json.dumps({"key": "not-an-array"}).encode(),
            headers={"Content-Type": "application/json", "X-API-Key": VALID_KEY},
        )
        assert resp.status_code == 422

    def test_rate_limit_returns_429(self, client):
        hit = False
        for _ in range(65):
            r = post_logs(client, [], api_key=VALID_KEY2)
            if r.status_code == 429:
                hit = True
                break
        assert hit, "Rate limit never triggered"

    def test_rate_limit_has_retry_after_header(self, client):
        for _ in range(65):
            r = post_logs(client, [], api_key=VALID_KEY2)
            if r.status_code == 429:
                assert "retry-after" in r.headers
                return
        pytest.fail("Rate limit never triggered")
