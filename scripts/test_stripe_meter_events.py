"""
Synthegria SIEM — Cyber Anomaly Log Generator
==============================================
Simulates an incoming API request (with X-API-Key header), resolves the
Stripe Customer ID via utils/auth.py, generates realistic anomaly log
batches, and reports each batch's line count to the Stripe "log_delivery"
billing meter.

Usage:
  python scripts/test_stripe_meter_events.py

Requirements:
  - STRIPE_SECRET_KEY environment variable set (sk_test_...)
  - utils/auth.py with a valid key → customer mapping
"""

import os
import sys
import time
import json
import random
import ipaddress
import stripe
from datetime import datetime, timezone

# Allow imports from the repo root regardless of where the script is run from
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils.auth import resolve_customer, AuthError

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

METER_EVENT_NAME = "log_delivery"
BATCH_COUNT      = 5
MIN_LINES        = 1000
MAX_LINES        = 5000

# ---------------------------------------------------------------------------
# Threat simulation data
# ---------------------------------------------------------------------------

ATTACK_TYPES = [
    "Brute Force", "SQL Injection", "Port Scan", "XSS Attempt",
    "Directory Traversal", "Command Injection", "DNS Tunneling",
    "Credential Stuffing", "LDAP Injection", "Reverse Shell",
    "Privilege Escalation", "Lateral Movement", "Data Exfiltration",
    "Ransomware Beacon", "Zero-Day Exploit",
]

SEVERITIES       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEVERITY_WEIGHTS = [20, 40, 30, 10]

PROTOCOLS = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS", "SSH", "FTP", "SMB"]

DESTINATIONS = [
    "10.0.0.1", "10.0.0.5", "10.0.1.100", "192.168.1.1",
    "192.168.1.254", "172.16.0.10", "172.16.0.20", "172.31.255.1",
]

USER_AGENTS = [
    "sqlmap/1.7.8#stable (https://sqlmap.org)",
    "Nikto/2.1.6", "masscan/1.3.2", "python-requests/2.31.0",
    "curl/7.88.1", "Mozilla/5.0 (compatible; Nmap Scripting Engine)", "-",
]

ACTIONS        = ["BLOCKED", "ALLOWED", "DETECTED", "ALERTED", "DROPPED"]
ACTION_WEIGHTS = [40, 15, 25, 15, 5]

SENSOR_NODES = [
    "siem-edge-01", "siem-edge-02", "siem-core-01",
    "fw-north", "fw-south", "ids-dmz", "ids-internal",
]

# ---------------------------------------------------------------------------
# Simulated HTTP request
# ---------------------------------------------------------------------------

def simulate_request(api_key: str) -> dict:
    """Return a minimal dict that mimics an incoming HTTP request object."""
    return {
        "method":  "POST",
        "path":    "/api/v1/logs/ingest",
        "headers": {
            "X-API-Key":     api_key,
            "Content-Type":  "application/json",
            "User-Agent":    "SynthegriaAgent/1.0",
        },
    }

# ---------------------------------------------------------------------------
# Log generation
# ---------------------------------------------------------------------------

def random_public_ip() -> str:
    while True:
        ip = ipaddress.IPv4Address(random.randint(0, 2**32 - 1))
        if ip.is_global:
            return str(ip)


def generate_log_line(ts: datetime) -> dict:
    return {
        "timestamp":   ts.isoformat(),
        "sensor":      random.choice(SENSOR_NODES),
        "source_ip":   random_public_ip(),
        "source_port": random.randint(1024, 65535),
        "dest_ip":     random.choice(DESTINATIONS),
        "dest_port":   random.choice([22, 23, 80, 443, 445, 1433, 3306, 3389, 8080, 8443]),
        "protocol":    random.choice(PROTOCOLS),
        "attack_type": random.choice(ATTACK_TYPES),
        "severity":    random.choices(SEVERITIES, weights=SEVERITY_WEIGHTS, k=1)[0],
        "action":      random.choices(ACTIONS, weights=ACTION_WEIGHTS, k=1)[0],
        "user_agent":  random.choice(USER_AGENTS),
        "event_id":    f"EVT-{random.randint(100000, 999999)}",
        "confidence":  round(random.uniform(0.55, 1.0), 2),
        "bytes_sent":  random.randint(64, 65536),
        "bytes_recv":  random.randint(0, 8192),
    }


def generate_batch(batch_num: int) -> list[dict]:
    line_count = random.randint(MIN_LINES, MAX_LINES)
    now = datetime.now(timezone.utc)
    print(f"\n{'='*70}")
    print(f"  Synthegria SIEM  |  Batch {batch_num}/{BATCH_COUNT}  |  {line_count:,} anomaly log lines")
    print(f"{'='*70}")
    logs = []
    for _ in range(line_count):
        jitter = random.randint(0, 600)
        ts = datetime.fromtimestamp(now.timestamp() - jitter, tz=timezone.utc)
        log = generate_log_line(ts)
        logs.append(log)
        print(json.dumps(log))
    return logs

# ---------------------------------------------------------------------------
# Stripe reporting
# ---------------------------------------------------------------------------

def report_meter_event(customer_id: str, line_count: int) -> None:
    print(f"\n>>> Reporting {line_count:,} lines to Stripe meter '{METER_EVENT_NAME}' ...")
    try:
        event = stripe.billing.MeterEvent.create(
            event_name=METER_EVENT_NAME,
            payload={
                "value": str(line_count),
                "stripe_customer_id": customer_id,
            },
            timestamp=int(time.time()),
        )
        print(f"    OK — identifier: {event.identifier}")
    except stripe.error.InvalidRequestError as e:
        print(f"    ERROR (InvalidRequest): {e.user_message}")
    except stripe.error.StripeError as e:
        print(f"    ERROR (Stripe): {e}")

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

TENANTS = [
    {"label": "Tenant 1", "api_key": "synthegria_test_key_1"},
    {"label": "Tenant 2", "api_key": "synthegria_test_key_2"},
]


def run_tenant(label: str, api_key: str, mode: str) -> None:
    separator = "─" * 70

    print(f"\n{'═'*70}")
    print(f"  {label}  —  simulating ingestion request")
    print(f"{'═'*70}")

    # Step 1 — Simulate request
    request = simulate_request(api_key)
    print(f"  {request['method']} {request['path']}")
    for k, v in request["headers"].items():
        print(f"    {k}: {v}")

    # Step 2 — Authenticate
    try:
        customer_id = resolve_customer(request["headers"].get("X-API-Key"))
        print(f"\n  Auth OK — resolved customer: {customer_id}")
    except AuthError as e:
        print(f"\n  Auth FAILED — {e}")
        return

    # Step 3 — Generate batches and report
    total_lines = 0
    for batch_num in range(1, BATCH_COUNT + 1):
        logs = generate_batch(batch_num)
        line_count = len(logs)
        total_lines += line_count
        report_meter_event(customer_id, line_count)

    print(f"\n{separator}")
    print(f"  {label} done — {total_lines:,} lines reported to customer {customer_id}")
    print(f"  Dashboard : https://dashboard.stripe.com/test/customers/{customer_id}")
    print(separator)


def main():
    stripe.api_key = os.environ.get("STRIPE_SECRET_KEY")
    if not stripe.api_key:
        print("ERROR: STRIPE_SECRET_KEY environment variable is not set.")
        sys.exit(1)

    mode = "LIVE" if stripe.api_key.startswith("sk_live_") else "TEST"

    print("╔══════════════════════════════════════════════════╗")
    print("║   Synthegria SIEM — Cyber Anomaly Log Generator  ║")
    print("╚══════════════════════════════════════════════════╝")
    print(f"  Stripe mode  : {mode}")
    print(f"  Meter        : {METER_EVENT_NAME}")
    print(f"  Tenants      : {len(TENANTS)}")
    print(f"  Batches/tenant: {BATCH_COUNT}")
    print(f"  Lines/batch  : {MIN_LINES:,} – {MAX_LINES:,} (random)")

    if mode == "LIVE":
        confirm = input("\nWARNING: LIVE key — real charges may apply. Proceed? [y/N] ").strip().lower()
        if confirm != "y":
            print("Aborted.")
            sys.exit(0)

    for tenant in TENANTS:
        run_tenant(tenant["label"], tenant["api_key"], mode)

    print(f"\n{'═'*70}")
    print(f"  All {len(TENANTS)} tenants complete.")
    print(f"  Meters : https://dashboard.stripe.com/test/billing/meters")
    print(f"{'═'*70}")


if __name__ == "__main__":
    main()
