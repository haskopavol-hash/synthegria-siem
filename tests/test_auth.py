"""
tests/test_auth.py — X-API-Key authentication and RFC 7235 contract.

Coverage
────────
  - Missing key          → 401
  - Invalid/unknown key  → 401
  - Valid key            → 200  (not a 401)
  - WWW-Authenticate header present on every 401
  - Response body has 'error' and 'detail' keys
  - Same contract applies to /v1/logs/bulk
"""

from __future__ import annotations

import json
import gzip

import pytest

from tests.conftest import VALID_KEY, BAD_KEY, make_logs, gz


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def plain_post(client, api_key=VALID_KEY, n=1):
    headers = {"Content-Type": "application/json"}
    if api_key is not None:
        headers["X-API-Key"] = api_key
    return client.post("/v1/logs", content=json.dumps(make_logs(n)).encode(), headers=headers)


def bulk_post(client, api_key=VALID_KEY, n=1):
    headers = {"Content-Type": "application/json", "Content-Encoding": "gzip"}
    if api_key is not None:
        headers["X-API-Key"] = api_key
    return client.post("/v1/logs/bulk", content=gz(make_logs(n)), headers=headers)


# ---------------------------------------------------------------------------
# /v1/logs  — plain endpoint
# ---------------------------------------------------------------------------

class TestPlainEndpointAuth:
    def test_missing_key_returns_401(self, client):
        resp = plain_post(client, api_key=None)
        assert resp.status_code == 401

    def test_invalid_key_returns_401(self, client):
        resp = plain_post(client, api_key=BAD_KEY)
        assert resp.status_code == 401

    def test_valid_key_does_not_return_401(self, client):
        resp = plain_post(client, api_key=VALID_KEY)
        assert resp.status_code == 200

    def test_401_has_www_authenticate_header(self, client):
        resp = plain_post(client, api_key=BAD_KEY)
        assert resp.status_code == 401
        www_auth = resp.headers.get("www-authenticate", "")
        assert "ApiKey" in www_auth, f"WWW-Authenticate missing or wrong: {www_auth!r}"

    def test_401_www_authenticate_includes_realm(self, client):
        resp = plain_post(client, api_key=None)
        assert "Synthegria" in resp.headers.get("www-authenticate", "")

    def test_401_body_has_error_field(self, client):
        resp = plain_post(client, api_key=BAD_KEY)
        assert "error" in resp.json()

    def test_401_body_has_detail_field(self, client):
        resp = plain_post(client, api_key=BAD_KEY)
        assert "detail" in resp.json()

    def test_401_error_value_is_unauthorized(self, client):
        resp = plain_post(client, api_key=BAD_KEY)
        assert resp.json()["error"] == "unauthorized"

    def test_401_body_does_not_leak_raw_key(self, client):
        resp = plain_post(client, api_key=BAD_KEY)
        body_text = resp.text
        assert BAD_KEY not in body_text


# ---------------------------------------------------------------------------
# /v1/logs/bulk  — bulk endpoint
# ---------------------------------------------------------------------------

class TestBulkEndpointAuth:
    def test_missing_key_returns_401(self, client):
        resp = bulk_post(client, api_key=None)
        assert resp.status_code == 401

    def test_invalid_key_returns_401(self, client):
        resp = bulk_post(client, api_key=BAD_KEY)
        assert resp.status_code == 401

    def test_bulk_401_has_www_authenticate(self, client):
        resp = bulk_post(client, api_key=BAD_KEY)
        assert "ApiKey" in resp.headers.get("www-authenticate", "")

    def test_bulk_401_body_contract(self, client):
        resp = bulk_post(client, api_key=BAD_KEY)
        body = resp.json()
        assert "error" in body
        assert "detail" in body
        assert body["error"] == "unauthorized"
