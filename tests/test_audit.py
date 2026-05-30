"""
tests/test_audit.py — GET /v1/audit structured audit log.

Coverage
────────
  - Returns a list
  - All required fields present
  - api_key is masked (not raw)
  - limit query parameter respected
  - 200 entry has customer_id and lines_received set
  - 401 entry has customer_id=null, lines_received=null
  - /healthz entry has api_key=null
  - Bulk entry (202) has lines_received set
"""

from __future__ import annotations

import json
import time

import pytest

from tests.conftest import VALID_KEY, BAD_KEY, make_logs, gz


def post_logs(client, logs=None, api_key=VALID_KEY):
    return client.post(
        "/v1/logs",
        content=json.dumps(logs or make_logs(3)).encode(),
        headers={"Content-Type": "application/json", "X-API-Key": api_key},
    )


def post_bulk(client, logs=None, api_key=VALID_KEY):
    return client.post(
        "/v1/logs/bulk",
        content=gz(logs or make_logs(5)),
        headers={
            "Content-Type": "application/json",
            "Content-Encoding": "gzip",
            "X-API-Key": api_key,
        },
    )


def latest_audit(client, path_filter: str | None = None) -> dict | None:
    resp = client.get("/v1/audit?limit=100")
    entries = resp.json()
    if path_filter:
        entries = [e for e in entries if isinstance(e, dict) and e.get("path") == path_filter]
    return entries[-1] if entries else None


# ---------------------------------------------------------------------------
# Basic structure
# ---------------------------------------------------------------------------

class TestAuditStructure:
    def test_returns_list(self, client):
        resp = client.get("/v1/audit")
        assert isinstance(resp.json(), list)

    def test_default_limit(self, client):
        resp = client.get("/v1/audit")
        assert len(resp.json()) <= 20

    def test_custom_limit(self, client):
        # Submit a few requests, then check limit is honoured
        for _ in range(5):
            post_logs(client)
        resp = client.get("/v1/audit?limit=2")
        assert len(resp.json()) <= 2

    def test_all_required_fields_present(self, client):
        post_logs(client)
        entry = latest_audit(client, "/v1/logs") or {}
        required = [
            "ts", "method", "path", "status_code", "duration_ms",
            "api_key", "customer_id", "lines_received", "anomaly_count", "ip",
        ]
        missing = [f for f in required if f not in entry]
        assert missing == [], f"Missing fields: {missing}"


# ---------------------------------------------------------------------------
# Key masking
# ---------------------------------------------------------------------------

class TestAuditKeyMasking:
    def test_api_key_is_masked_not_raw(self, client):
        post_logs(client)
        entry = latest_audit(client, "/v1/logs") or {}
        audit_key = entry.get("api_key", "")
        assert audit_key != VALID_KEY, "Raw API key must never appear in audit log"

    def test_api_key_mask_contains_ellipsis(self, client):
        post_logs(client)
        entry = latest_audit(client, "/v1/logs") or {}
        assert "..." in entry.get("api_key", "")

    def test_healthz_has_null_api_key(self, client):
        client.get("/healthz")
        entry = latest_audit(client, "/healthz") or {}
        assert entry.get("api_key") is None


# ---------------------------------------------------------------------------
# Per-request data population
# ---------------------------------------------------------------------------

class TestAuditData:
    def test_success_entry_has_customer_id(self, client):
        n = 4
        post_logs(client, make_logs(n))
        entry = latest_audit(client, "/v1/logs") or {}
        assert entry.get("customer_id") is not None
        assert entry.get("status_code") == 200

    def test_success_entry_lines_received_matches_batch(self, client):
        n = 6
        post_logs(client, make_logs(n))
        entry = latest_audit(client, "/v1/logs") or {}
        assert entry.get("lines_received") == n

    def test_failed_auth_entry_customer_id_null(self, client):
        post_logs(client, make_logs(1), api_key=BAD_KEY)
        entry = latest_audit(client, "/v1/logs") or {}
        assert entry.get("status_code") == 401
        assert entry.get("customer_id") is None

    def test_failed_auth_entry_lines_received_null(self, client):
        post_logs(client, make_logs(1), api_key=BAD_KEY)
        entry = latest_audit(client, "/v1/logs") or {}
        assert entry.get("lines_received") is None

    def test_bulk_entry_has_correct_lines_received(self, client):
        n = 15
        post_bulk(client, make_logs(n))
        entry = latest_audit(client, "/v1/logs/bulk") or {}
        assert entry.get("lines_received") == n

    def test_bulk_entry_status_code_is_202(self, client):
        post_bulk(client, make_logs(5))
        entry = latest_audit(client, "/v1/logs/bulk") or {}
        assert entry.get("status_code") == 202

    def test_anomaly_count_recorded_in_audit(self, client):
        post_logs(client, make_logs(5))
        entry = latest_audit(client, "/v1/logs") or {}
        assert "anomaly_count" in entry
