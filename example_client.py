"""
example_client.py — Reference integration for the Synthegria M2M Core API
===========================================================================

PURPOSE
-------
This script is the canonical reference for any autonomous server, edge
collector, or third-party security appliance that needs to ship log batches to
the Synthegria M2M Core bulk ingestion endpoint.

Copy-paste this file as your starting point.  Every step is annotated so
your integration team understands exactly why each choice was made.

DEPENDENCIES
------------
Zero.  This script uses only the Python 3.11 standard library.  No pip
install required.

QUICK START
-----------
    # Against the local dev server (default):
    python example_client.py

    # Against a remote deployment:
    SYNTHEGRIA_BASE_URL=https://synthegria-siem.fly.dev \\
    SYNTHEGRIA_API_KEY=synthegria_prod_key_xyz \\
    python example_client.py

ENVIRONMENT VARIABLES
---------------------
  SYNTHEGRIA_API_KEY    Your tenant API key.  Required for authenticated calls.
                        Default: synthegria_test_key_1 (local dev only).
  SYNTHEGRIA_BASE_URL   Base URL of the Synthegria M2M Core API.
                        Default: http://localhost:8000
  SYNTHEGRIA_BATCH_SIZE Number of log lines per batch.  Default: 500.
  SYNTHEGRIA_BATCHES    How many batches to send in this run.  Default: 3.
  SYNTHEGRIA_DRY_RUN    Set to "1" to build + compress batches but skip the
                        network send.  Useful for testing pipeline throughput.

WHAT THIS SCRIPT DEMONSTRATES
------------------------------
  1.  Generating realistic structured security log lines
  2.  Serialising the batch to compact JSON (no unnecessary whitespace)
  3.  Compressing with gzip (level 6 — good ratio / speed tradeoff)
  4.  Setting the required HTTP headers:
        Content-Type: application/json
        Content-Encoding: gzip
        X-API-Key: <your key>
  5.  POSTing to POST /v1/logs/bulk
  6.  Parsing the success response envelope:
        status, customer_id, lines_received, meter_event_id,
        anomaly_count, anomalies[], compression_ratio
  7.  Handling every documented error status:
        400 Bad Request       — malformed or corrupt payload
        401 Unauthorized      — missing or invalid API key
        413 Request Too Large — compressed batch > 10 MB (split and retry)
        415 Unsupported Media — missing Content-Encoding: gzip
        422 Unprocessable     — body is not a JSON array
        429 Too Many Requests — rate limit hit; honour Retry-After
        502 Bad Gateway       — upstream Stripe error; retry with backoff
  8.  Retry logic with exponential back-off + jitter for transient errors
"""

from __future__ import annotations

import gzip
import json
import logging
import math
import os
import random
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

# ─────────────────────────────────────────────────────────────────────────────
# Configuration — override via environment variables
# ─────────────────────────────────────────────────────────────────────────────

API_KEY    = os.environ.get("SYNTHEGRIA_API_KEY",    "synthegria_test_key_1")
BASE_URL   = os.environ.get("SYNTHEGRIA_BASE_URL",   "http://localhost:8000").rstrip("/")
BATCH_SIZE = int(os.environ.get("SYNTHEGRIA_BATCH_SIZE", "500"))
BATCHES    = int(os.environ.get("SYNTHEGRIA_BATCHES",    "3"))
DRY_RUN    = os.environ.get("SYNTHEGRIA_DRY_RUN", "0") == "1"

BULK_ENDPOINT = f"{BASE_URL}/v1/logs/bulk"

# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("synthegria.client")

# ─────────────────────────────────────────────────────────────────────────────
# Retry configuration
# ─────────────────────────────────────────────────────────────────────────────

MAX_RETRIES       = 4       # maximum delivery attempts per batch
BACKOFF_BASE_S    = 1.0     # initial back-off delay in seconds
BACKOFF_MAX_S     = 60.0    # cap on back-off delay
BACKOFF_JITTER    = 0.25    # add up to 25 % random jitter to each delay

# ─────────────────────────────────────────────────────────────────────────────
# Log generation — replace this section with your real log source
# ─────────────────────────────────────────────────────────────────────────────

_ATTACK_TYPES = [
    "Port Scan", "DNS Tunneling", "Ransomware Beacon",
    "C2 Callback", "Data Exfiltration", "Lateral Movement",
    "Credential Access", "Persistence Mechanism",
]
_SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
_PROTOCOLS  = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS", "SSH", "FTP"]
_ACTIONS    = ["BLOCK", "ALLOW", "ALERT", "DROP", "QUARANTINE"]


def _random_ipv4() -> str:
    """Generate a random globally-routable IPv4 address."""
    while True:
        parts = [random.randint(1, 254) for _ in range(4)]
        # Skip RFC-1918 private ranges
        if parts[0] not in (10, 127, 169, 172, 192):
            return ".".join(map(str, parts))


def build_log_line(sequence: int) -> dict[str, Any]:
    """
    Return one structured security event dict.

    In production, replace this function with your actual log collector —
    e.g. parse a syslog stream, consume a Kafka topic, or tail a file.
    The only requirement is that the function returns a JSON-serialisable dict.
    """
    return {
        "ts":          datetime.now(timezone.utc).isoformat(),
        "seq":         sequence,
        "src_ip":      _random_ipv4(),
        "dst_ip":      _random_ipv4(),
        "src_port":    random.randint(1024, 65535),
        "dst_port":    random.choice([22, 80, 443, 3306, 5432, 8080, 8443]),
        "protocol":    random.choice(_PROTOCOLS),
        "action":      random.choice(_ACTIONS),
        "attack_type": random.choice(_ATTACK_TYPES),
        "severity":    random.choice(_SEVERITIES),
        "bytes_in":    random.randint(64, 65536),
        "bytes_out":   random.randint(64, 65536),
        "event_id":    f"EVT-{random.randint(10_000_000, 99_999_999)}",
        "sensor_id":   f"SENSOR-{random.randint(1, 32):02d}",
    }


def build_batch(size: int, offset: int = 0) -> list[dict[str, Any]]:
    """Return a list of *size* log-line dicts."""
    return [build_log_line(offset + i) for i in range(size)]

# ─────────────────────────────────────────────────────────────────────────────
# Serialisation + compression
# ─────────────────────────────────────────────────────────────────────────────

def serialise_and_compress(batch: list[dict]) -> tuple[bytes, int]:
    """
    Serialise *batch* to compact JSON and compress with gzip level 6.

    Returns
    -------
    compressed : bytes
        The gzip-compressed payload ready to POST.
    raw_size : int
        Uncompressed byte length (useful for logging the compression ratio).

    Notes
    -----
    - `separators=(',', ':')` removes all whitespace from the JSON output,
      reducing the uncompressed size before gzip even runs.
    - gzip level 6 is the sweet spot between compression ratio and CPU cost.
      Use level 1 for maximum speed, level 9 for maximum compression.
    - The API enforces a 10 MB limit on the *compressed* payload.  If you
      exceed it, split the batch in half and retry each half separately.
    """
    raw: bytes     = json.dumps(batch, separators=(",", ":")).encode("utf-8")
    compressed: bytes = gzip.compress(raw, compresslevel=6)
    return compressed, len(raw)

# ─────────────────────────────────────────────────────────────────────────────
# HTTP delivery
# ─────────────────────────────────────────────────────────────────────────────

def _backoff_delay(attempt: int) -> float:
    """
    Compute an exponential back-off delay with jitter.

    attempt=0 → ~1 s,  attempt=1 → ~2 s,  attempt=2 → ~4 s, …
    Capped at BACKOFF_MAX_S and randomised by ±BACKOFF_JITTER.
    """
    base   = min(BACKOFF_BASE_S * math.pow(2, attempt), BACKOFF_MAX_S)
    jitter = base * BACKOFF_JITTER * (2 * random.random() - 1)
    return max(0.0, base + jitter)


def send_batch(
    compressed: bytes,
    raw_size:   int,
    batch_num:  int,
) -> dict[str, Any] | None:
    """
    Deliver one compressed batch to POST /v1/logs/bulk with retry logic.

    Returns the parsed JSON response dict on success, or None if all retries
    were exhausted.

    Error handling strategy
    -----------------------
    400  Malformed payload — do NOT retry; fix the serialiser.
    401  Bad API key — do NOT retry; check SYNTHEGRIA_API_KEY.
    413  Payload too large — split the batch; do NOT retry as-is.
    415  Missing Content-Encoding — do NOT retry; this is a code bug.
    422  Body not a JSON array — do NOT retry; fix the serialiser.
    429  Rate limited — sleep Retry-After seconds then retry.
    502  Upstream Stripe error — retry with back-off.
    5xx  Server error — retry with back-off.
    """
    # ── Build the HTTP request ────────────────────────────────────────────────
    # Three headers are mandatory for the bulk endpoint:
    #
    #   Content-Type: application/json      — tells the server the decompressed
    #                                         body is JSON (not a binary blob).
    #   Content-Encoding: gzip              — tells the server to decompress the
    #                                         body before parsing.
    #   X-API-Key: <key>                    — tenant authentication.
    #
    headers = {
        "Content-Type":     "application/json",
        "Content-Encoding": "gzip",
        "X-API-Key":        API_KEY,
    }

    compressed_kb  = len(compressed) / 1024
    raw_kb         = raw_size        / 1024
    ratio          = raw_size / len(compressed) if compressed else 0

    log.info(
        "Batch %d/%d  raw=%.1f KB  compressed=%.1f KB  ratio=%.2fx",
        batch_num, BATCHES, raw_kb, compressed_kb, ratio,
    )

    for attempt in range(MAX_RETRIES):
        req = urllib.request.Request(
            BULK_ENDPOINT,
            data    = compressed,
            method  = "POST",
            headers = headers,
        )

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                body: dict = json.loads(resp.read())

            # ── Parse success response ────────────────────────────────────────
            lines    = body.get("lines_received", 0)
            anomalies = body.get("anomaly_count", 0)
            meter_id  = body.get("meter_event_id") or "(empty batch)"

            log.info(
                "  ✓ accepted  lines=%d  anomalies=%d  "
                "compression=%s  meter_event=%s",
                lines, anomalies,
                body.get("compression_ratio", "?"),
                meter_id,
            )

            # ── Print anomaly details if any were found ───────────────────────
            if anomalies:
                log.warning("  ⚠ %d anomal%s detected:", anomalies,
                            "y" if anomalies == 1 else "ies")
                for a in body.get("anomalies", []):
                    log.warning(
                        "    [%s] %s — %s",
                        a.get("severity", "?"),
                        a.get("type",     "?"),
                        a.get("matched_pattern", "?"),
                    )

            return body

        except urllib.error.HTTPError as exc:
            body_bytes = exc.read()
            try:
                err = json.loads(body_bytes)
                detail = err.get("detail") or err.get("error") or str(err)
            except Exception:
                detail = body_bytes.decode(errors="replace")[:200]

            # ── Non-retriable errors ──────────────────────────────────────────
            if exc.code == 401:
                log.error("  ✗ 401 Unauthorized — check SYNTHEGRIA_API_KEY: %s", detail)
                return None   # no point retrying; key is wrong

            if exc.code == 413:
                log.error(
                    "  ✗ 413 Payload Too Large (%.1f KB compressed) — "
                    "reduce SYNTHEGRIA_BATCH_SIZE: %s", compressed_kb, detail
                )
                return None   # must split the batch before retrying

            if exc.code in (400, 415, 422):
                log.error("  ✗ %d client error (not retriable): %s", exc.code, detail)
                return None

            # ── Rate limit — honour Retry-After ──────────────────────────────
            if exc.code == 429:
                retry_after = int(exc.headers.get("Retry-After", "60"))
                log.warning(
                    "  ✗ 429 Rate Limited — waiting %d s (Retry-After) "
                    "[attempt %d/%d]", retry_after, attempt + 1, MAX_RETRIES,
                )
                time.sleep(retry_after)
                continue  # retry immediately after the window resets

            # ── Retriable server errors (502, 503, 504, …) ───────────────────
            delay = _backoff_delay(attempt)
            log.warning(
                "  ✗ %d server error — retrying in %.1f s "
                "[attempt %d/%d]: %s",
                exc.code, delay, attempt + 1, MAX_RETRIES, detail,
            )
            time.sleep(delay)

        except urllib.error.URLError as exc:
            # Network-level failure (connection refused, DNS, timeout)
            delay = _backoff_delay(attempt)
            log.warning(
                "  ✗ network error — retrying in %.1f s [attempt %d/%d]: %s",
                delay, attempt + 1, MAX_RETRIES, exc.reason,
            )
            time.sleep(delay)

    log.error("  ✗ batch %d failed after %d attempts", batch_num, MAX_RETRIES)
    return None

# ─────────────────────────────────────────────────────────────────────────────
# Liveness check — optional but useful at startup
# ─────────────────────────────────────────────────────────────────────────────

def check_liveness() -> bool:
    """
    Verify the API is reachable before sending any batches.

    Returns True if /healthz responds 200, False otherwise.
    """
    url = f"{BASE_URL}/healthz"
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            body = json.loads(resp.read())
        if body.get("status") == "ok":
            log.info("Liveness check passed  url=%s", url)
            return True
        log.error("Liveness check: unexpected body %s", body)
        return False
    except Exception as exc:
        log.error("Liveness check failed  url=%s  error=%s", url, exc)
        return False

# ─────────────────────────────────────────────────────────────────────────────
# Main integration loop
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    """
    End-to-end integration demonstration:

      1. Verify the API is reachable
      2. For each batch:
         a. Generate BATCH_SIZE synthetic log lines
         b. Serialise to compact JSON and compress with gzip
         c. POST to /v1/logs/bulk with the correct headers
         d. Log the response (lines accepted, anomalies, meter event)
      3. Print a final delivery summary
    """
    print("=" * 60)
    print("  Synthegria M2M Core — Example Client")
    print("=" * 60)
    print(f"  Endpoint  : {BULK_ENDPOINT}")
    print(f"  API key   : {API_KEY[:6]}...{API_KEY[-4:]}")
    print(f"  Batches   : {BATCHES} × {BATCH_SIZE:,} lines")
    print(f"  Dry run   : {'YES — no network calls' if DRY_RUN else 'NO — live delivery'}")
    print("=" * 60)

    # ── Step 1: liveness check ────────────────────────────────────────────────
    if not DRY_RUN and not check_liveness():
        raise SystemExit(
            f"Cannot reach {BASE_URL} — "
            "is the server running?  Set SYNTHEGRIA_BASE_URL to override."
        )

    # ── Step 2: send batches ──────────────────────────────────────────────────
    total_lines    = 0
    total_anomalies = 0
    failures       = 0
    t_start        = time.perf_counter()

    for batch_num in range(1, BATCHES + 1):
        offset = (batch_num - 1) * BATCH_SIZE
        batch  = build_batch(BATCH_SIZE, offset)

        # Serialise and compress — this step is identical whether or not we
        # actually send (useful for benchmarking the pipeline in dry-run mode).
        compressed, raw_size = serialise_and_compress(batch)

        if DRY_RUN:
            ratio = raw_size / len(compressed) if compressed else 0
            log.info(
                "[DRY RUN] Batch %d/%d  raw=%.1f KB  compressed=%.1f KB  "
                "ratio=%.2fx",
                batch_num, BATCHES,
                raw_size / 1024, len(compressed) / 1024, ratio,
            )
            total_lines += BATCH_SIZE
            continue

        result = send_batch(compressed, raw_size, batch_num)

        if result is None:
            failures += 1
        else:
            total_lines     += result.get("lines_received", 0)
            total_anomalies += result.get("anomaly_count",  0)

    # ── Step 3: summary ───────────────────────────────────────────────────────
    elapsed = time.perf_counter() - t_start
    print()
    print("=" * 60)
    print("  Delivery Summary")
    print("=" * 60)
    print(f"  Batches sent    : {BATCHES - failures}/{BATCHES}")
    print(f"  Lines delivered : {total_lines:,}")
    print(f"  Anomalies found : {total_anomalies}")
    print(f"  Failures        : {failures}")
    print(f"  Elapsed         : {elapsed:.2f} s")
    if total_lines:
        print(f"  Throughput      : {total_lines / elapsed:,.0f} lines/s")
    print("=" * 60)

    if failures:
        raise SystemExit(f"{failures} batch(es) failed — see logs above for details")


if __name__ == "__main__":
    main()
