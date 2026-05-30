"""
Synthegria SIEM Python SDK
==========================
Official Python client for the Synthegria log ingestion API.

Quick start
-----------
    from synthegria import SynthegriaClient

    client = SynthegriaClient(
        api_key="synthegria_<tenant>_<token>",
        base_url="https://your-app.onrender.com",
    )

    # Real-time synchronous ingestion
    result = client.ingest(logs)
    print(result["anomaly_count"])          # e.g. 2
    print(result["ai_analysis"]["summary"]) # AI threat summary

    # High-throughput async bulk ingestion
    job = client.ingest_bulk(logs)
    result = job.wait(timeout=60)           # blocks until done
    print(result["meter_event_id"])

Exceptions
----------
    SynthegriaError    — base for all SDK errors
    AuthError          — 401 Unauthorized (bad or missing API key)
    RateLimitError     — 429 Too Many Requests
    BulkJobError       — bulk job finished with status="failed"
"""

from .client import SynthegriaClient, BulkJob
from .exceptions import SynthegriaError, AuthError, RateLimitError, BulkJobError

__all__ = [
    "SynthegriaClient",
    "BulkJob",
    "SynthegriaError",
    "AuthError",
    "RateLimitError",
    "BulkJobError",
]

__version__ = "1.0.0"
