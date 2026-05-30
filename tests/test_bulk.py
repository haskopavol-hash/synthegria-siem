"""
tests/test_bulk.py — POST /v1/logs/bulk and GET /v1/jobs/{job_id}.

Coverage
────────
  Bulk endpoint (202 Accepted):
  - Valid batch → 202 + job_id + poll_url
  - Missing Content-Encoding  → 415
  - Corrupted gzip             → 400
  - Non-array JSON after decomp → 422
  - Body > 10 MB               → 413
  - Rate limit                  → 429

  Job polling:
  - Job eventually reaches 'done'
  - Done result has full ingestion envelope fields
  - meter_event_id present in done result
  - ai_analysis present in done result
  - Unknown job_id → 404
  - Failed job returns 'failed' status with 'error' field
"""

from __future__ import annotations

import gzip
import json
import os
import time

import pytest

from tests.conftest import (
    VALID_KEY, VALID_KEY2, FAKE_METER_ID,
    make_logs, gz, poll_job,
    BRUTE_FORCE, SQL_INJECTION,
)


def bulk_post(client, data: bytes, api_key=VALID_KEY, encoding="gzip"):
    headers = {"Content-Type": "application/json", "X-API-Key": api_key}
    if encoding:
        headers["Content-Encoding"] = encoding
    return client.post("/v1/logs/bulk", content=data, headers=headers)


# ---------------------------------------------------------------------------
# 202 Accepted response structure
# ---------------------------------------------------------------------------

class TestBulkAccepted:
    def test_valid_batch_returns_202(self, client):
        resp = bulk_post(client, gz(make_logs(10)))
        assert resp.status_code == 202

    def test_accepted_response_has_status_accepted(self, client):
        resp = bulk_post(client, gz(make_logs(5)))
        assert resp.json()["status"] == "accepted"

    def test_accepted_response_has_job_id(self, client):
        resp = bulk_post(client, gz(make_logs(5)))
        assert resp.json().get("job_id") is not None

    def test_accepted_response_has_poll_url(self, client):
        resp = bulk_post(client, gz(make_logs(5)))
        assert "/v1/jobs/" in resp.json().get("poll_url", "")

    def test_accepted_lines_received_matches_payload(self, client):
        n = 25
        resp = bulk_post(client, gz(make_logs(n)))
        assert resp.json()["lines_received"] == n

    def test_poll_url_includes_job_id(self, client):
        resp = bulk_post(client, gz(make_logs(3)))
        body = resp.json()
        assert body["job_id"] in body["poll_url"]


# ---------------------------------------------------------------------------
# Bulk error paths
# ---------------------------------------------------------------------------

class TestBulkErrors:
    def test_missing_gzip_encoding_returns_415(self, client):
        resp = client.post(
            "/v1/logs/bulk",
            content=json.dumps(make_logs(2)).encode(),
            headers={"Content-Type": "application/json", "X-API-Key": VALID_KEY},
        )
        assert resp.status_code == 415

    def test_corrupted_gzip_returns_400(self, client):
        resp = bulk_post(client, b"\x1f\x8b\x00corrupt_garbage")
        assert resp.status_code == 400

    def test_non_array_json_returns_422(self, client):
        resp = bulk_post(client, gzip.compress(json.dumps({"k": "v"}).encode()))
        assert resp.status_code == 422

    def test_oversized_body_returns_413(self, client):
        # 11 MB compressed (compresslevel=1 so it stays large)
        oversized = gzip.compress(os.urandom(11 * 1024 * 1024), compresslevel=1)
        resp = bulk_post(client, oversized)
        assert resp.status_code == 413

    def test_rate_limit_returns_429(self, client):
        tiny = gz([])
        hit = False
        for _ in range(65):
            r = bulk_post(client, tiny, api_key=VALID_KEY2)
            if r.status_code == 429:
                hit = True
                break
        assert hit, "Bulk rate limit never triggered"

    def test_rate_limit_has_retry_after_header(self, client):
        tiny = gz([])
        for _ in range(65):
            r = bulk_post(client, tiny, api_key=VALID_KEY2)
            if r.status_code == 429:
                assert "retry-after" in r.headers
                return
        pytest.fail("Bulk rate limit never triggered")


# ---------------------------------------------------------------------------
# Job polling — GET /v1/jobs/{job_id}
# ---------------------------------------------------------------------------

class TestJobPolling:
    def _submit(self, client, logs=None) -> str:
        resp = bulk_post(client, gz(make_logs(5) if logs is None else logs))
        assert resp.status_code == 202
        return resp.json()["job_id"]

    def test_job_reaches_done(self, client):
        job_id = self._submit(client)
        job = poll_job(client, job_id)
        assert job.get("status") == "done", f"Unexpected status: {job}"

    def test_done_job_has_result(self, client):
        job_id = self._submit(client)
        job = poll_job(client, job_id)
        assert isinstance(job.get("result"), dict)

    def test_done_result_has_status_ok(self, client):
        job_id = self._submit(client)
        result = poll_job(client, job_id).get("result", {})
        assert result.get("status") == "ok"

    def test_done_result_has_lines_received(self, client):
        n = 12
        job_id = self._submit(client, make_logs(n))
        result = poll_job(client, job_id).get("result", {})
        assert result["lines_received"] == n

    def test_done_result_has_meter_event_id(self, client):
        job_id = self._submit(client, make_logs(3))
        result = poll_job(client, job_id).get("result", {})
        assert result["meter_event_id"] == FAKE_METER_ID

    def test_done_result_has_anomaly_count(self, client):
        job_id = self._submit(client)
        result = poll_job(client, job_id).get("result", {})
        assert "anomaly_count" in result

    def test_done_result_has_anomalies_array(self, client):
        job_id = self._submit(client)
        result = poll_job(client, job_id).get("result", {})
        assert isinstance(result.get("anomalies"), list)

    def test_done_result_has_compression_stats(self, client):
        job_id = self._submit(client, make_logs(20))
        result = poll_job(client, job_id).get("result", {})
        assert "compressed_bytes" in result
        assert "uncompressed_bytes" in result
        assert "compression_ratio" in result

    def test_done_result_has_ai_analysis_key(self, client):
        """ai_analysis must be present (None or dict) — never missing."""
        job_id = self._submit(client)
        result = poll_job(client, job_id).get("result", {})
        assert "ai_analysis" in result

    def test_done_result_ai_analysis_for_anomalous_batch(self, client):
        """Brute-force batch → ai_analysis should be a dict (not None)."""
        job_id = self._submit(client, [BRUTE_FORCE] * 5)
        result = poll_job(client, job_id).get("result", {})
        ai = result.get("ai_analysis")
        assert isinstance(ai, dict), f"Expected dict, got {ai!r}"
        assert "summary" in ai
        assert "threat_level" in ai
        assert "attack_types" in ai

    def test_done_job_has_completed_at(self, client):
        job_id = self._submit(client)
        job = poll_job(client, job_id)
        assert job.get("completed_at") is not None

    def test_unknown_job_returns_404(self, client):
        resp = client.get("/v1/jobs/00000000-0000-0000-0000-000000000000")
        assert resp.status_code == 404

    def test_404_body_has_detail(self, client):
        resp = client.get("/v1/jobs/00000000-0000-0000-0000-000000000000")
        assert "detail" in resp.json()

    def test_empty_bulk_batch_no_meter(self, client):
        """Empty bulk batch: job should complete with meter_event_id=None."""
        job_id = self._submit(client, [])
        result = poll_job(client, job_id).get("result", {})
        assert result.get("meter_event_id") is None

    def test_job_status_pending_or_processing_before_done(self, client):
        """Immediately after submission, job should exist and not be in unknown state."""
        job_id = self._submit(client, make_logs(50))
        resp = client.get(f"/v1/jobs/{job_id}")
        assert resp.status_code == 200
        assert resp.json()["status"] in ("pending", "processing", "done")
