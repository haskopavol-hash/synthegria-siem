"""
sdk/python/synthegria/client.py — SynthegriaClient implementation.

Zero external dependencies beyond the Python standard library.
"""

from __future__ import annotations

import gzip
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from .exceptions import AuthError, BulkJobError, RateLimitError, SynthegriaError

DEFAULT_BASE_URL = "https://your-app.onrender.com"
DEFAULT_TIMEOUT  = 30.0   # seconds
DEFAULT_JOB_POLL_TIMEOUT   = 60.0   # seconds
DEFAULT_JOB_POLL_INTERVAL  = 0.5    # seconds


@dataclass
class BulkJob:
    """
    Handle returned by :meth:`SynthegriaClient.ingest_bulk`.

    Attributes
    ----------
    job_id          : Unique job identifier (UUID).
    lines_received  : Number of log lines accepted by the server.
    poll_url        : Relative URL for status polling.
    """

    job_id:         str
    lines_received: int
    poll_url:       str
    _client:        Any = field(repr=False)

    def wait(
        self,
        timeout: float = DEFAULT_JOB_POLL_TIMEOUT,
        poll_interval: float = DEFAULT_JOB_POLL_INTERVAL,
    ) -> dict[str, Any]:
        """
        Block until the server marks the job *done* and return the result dict.

        Parameters
        ----------
        timeout       : Maximum seconds to wait before raising TimeoutError.
        poll_interval : Seconds between each status check.

        Returns
        -------
        dict
            The ``result`` envelope (same shape as :meth:`SynthegriaClient.ingest`
            response, with ``ai_analysis`` included).

        Raises
        ------
        BulkJobError  : The job finished with status="failed".
        TimeoutError  : The job did not complete within *timeout* seconds.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status = self._client.get_job(self.job_id)
            if status["status"] == "done":
                return status["result"]
            if status["status"] == "failed":
                raise BulkJobError(self.job_id, status.get("error", "unknown"))
            time.sleep(poll_interval)
        raise TimeoutError(
            f"Bulk job '{self.job_id}' did not complete within {timeout:.0f}s."
        )

    def __repr__(self) -> str:
        return (
            f"BulkJob(job_id={self.job_id!r}, "
            f"lines_received={self.lines_received})"
        )


class SynthegriaClient:
    """
    Synchronous HTTP client for the Synthegria SIEM log ingestion API.

    Parameters
    ----------
    api_key  : Tenant API key (``X-API-Key`` header).
    base_url : Base URL of your deployed Synthegria instance.
    timeout  : Request timeout in seconds.

    Examples
    --------
    >>> client = SynthegriaClient(
    ...     api_key="synthegria_acme_abc123",
    ...     base_url="https://siem.acme.io",
    ... )
    >>> result = client.ingest([{"message": "login failed", "source_ip": "1.2.3.4"}])
    >>> print(result["anomaly_count"])
    """

    def __init__(
        self,
        api_key:  str,
        base_url: str   = DEFAULT_BASE_URL,
        timeout:  float = DEFAULT_TIMEOUT,
    ) -> None:
        if not api_key:
            raise ValueError("api_key must be a non-empty string.")
        self.api_key  = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout  = timeout

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _request(
        self,
        method:        str,
        path:          str,
        body:          bytes | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, Any] | list[Any]:
        url = self.base_url + path
        headers: dict[str, str] = {
            "X-API-Key":    self.api_key,
            "Content-Type": "application/json",
            **(extra_headers or {}),
        }
        req = urllib.request.Request(url, data=body, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            raw   = exc.read().decode(errors="replace")
            retry = exc.headers.get("Retry-After")
            try:
                detail = json.loads(raw).get("detail", raw)
            except Exception:
                detail = raw
            if exc.code == 401:
                raise AuthError(detail) from exc
            if exc.code == 429:
                raise RateLimitError(
                    detail,
                    retry_after=int(retry) if retry else None,
                ) from exc
            raise SynthegriaError(detail, status_code=exc.code) from exc
        except urllib.error.URLError as exc:
            raise SynthegriaError(f"Network error: {exc.reason}") from exc

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def ingest(self, logs: list[dict[str, Any]]) -> dict[str, Any]:
        """
        Send a plain JSON batch of log lines for **synchronous** processing.

        The server runs anomaly detection and AI analysis inline and returns
        the full result envelope immediately.

        Parameters
        ----------
        logs : List of log-line dicts.  Each entry can contain any fields
               (``timestamp``, ``source_ip``, ``message``, etc.).

        Returns
        -------
        dict with keys:
          - ``status``          — ``"ok"``
          - ``customer_id``     — Stripe Customer ID
          - ``lines_received``  — int
          - ``meter_event_id``  — Stripe meter event ID (or None for empty batch)
          - ``anomaly_count``   — int
          - ``anomalies``       — list of anomaly dicts
          - ``ai_analysis``     — AI threat summary dict, or None

        Raises
        ------
        AuthError        : Invalid or missing API key.
        RateLimitError   : Rate limit exceeded.
        SynthegriaError  : Any other API error.
        """
        body = json.dumps(logs).encode()
        return self._request("POST", "/v1/logs", body=body)  # type: ignore[return-value]

    def ingest_bulk(self, logs: list[dict[str, Any]]) -> BulkJob:
        """
        Submit a gzip-compressed batch for **asynchronous** background processing.

        The server responds with 202 Accepted immediately.  Use
        :meth:`BulkJob.wait` to block until processing completes, or call
        :meth:`get_job` repeatedly to poll manually.

        Parameters
        ----------
        logs : List of log-line dicts (same format as :meth:`ingest`).

        Returns
        -------
        BulkJob
            Handle with :attr:`~BulkJob.job_id` and a :meth:`~BulkJob.wait`
            method.

        Raises
        ------
        AuthError        : Invalid or missing API key.
        RateLimitError   : Rate limit exceeded.
        SynthegriaError  : Queue full (503) or other API error.
        """
        compressed = gzip.compress(json.dumps(logs).encode())
        result = self._request(
            "POST", "/v1/logs/bulk",
            body=compressed,
            extra_headers={"Content-Encoding": "gzip"},
        )
        assert isinstance(result, dict)
        return BulkJob(
            job_id=result["job_id"],
            lines_received=result["lines_received"],
            poll_url=result["poll_url"],
            _client=self,
        )

    def get_job(self, job_id: str) -> dict[str, Any]:
        """
        Retrieve the current status and (when done) result of a bulk job.

        Parameters
        ----------
        job_id : UUID string returned by :meth:`ingest_bulk`.

        Returns
        -------
        dict with keys:
          - ``status``        — ``"pending" | "processing" | "done" | "failed"``
          - ``job_id``        — echo of the input
          - ``lines_received``— int
          - ``created_at``    — ISO-8601 timestamp
          - ``result``        — full ingestion envelope (when ``status=="done"``)
          - ``error``         — error message (when ``status=="failed"``)

        Raises
        ------
        SynthegriaError(status_code=404) : Job not found or expired.
        """
        return self._request("GET", f"/v1/jobs/{job_id}")  # type: ignore[return-value]

    def get_audit(self, limit: int = 20) -> list[dict[str, Any]]:
        """
        Fetch the last *limit* structured audit log entries.

        Parameters
        ----------
        limit : Number of entries to return (max 100).
        """
        result = self._request("GET", f"/v1/audit?limit={limit}")
        return result  # type: ignore[return-value]

    def healthz(self) -> dict[str, Any]:
        """Check the API liveness.  Returns ``{"status": "ok"}``."""
        return self._request("GET", "/healthz")  # type: ignore[return-value]

    def __repr__(self) -> str:
        masked = f"{self.api_key[:6]}...{self.api_key[-4:]}" if len(self.api_key) > 10 else "***"
        return f"SynthegriaClient(api_key={masked!r}, base_url={self.base_url!r})"
