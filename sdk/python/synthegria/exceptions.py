"""sdk/python/synthegria/exceptions.py — SDK exception hierarchy."""

from __future__ import annotations


class SynthegriaError(Exception):
    """Base class for all Synthegria SDK errors."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class AuthError(SynthegriaError):
    """Raised when the API returns 401 Unauthorized."""

    def __init__(self, message: str = "Invalid or missing API key.") -> None:
        super().__init__(message, status_code=401)


class RateLimitError(SynthegriaError):
    """Raised when the API returns 429 Too Many Requests."""

    def __init__(self, message: str, retry_after: int | None = None) -> None:
        super().__init__(message, status_code=429)
        self.retry_after = retry_after


class BulkJobError(SynthegriaError):
    """Raised when a bulk job finishes with status='failed'."""

    def __init__(self, job_id: str, reason: str) -> None:
        super().__init__(f"Bulk job '{job_id}' failed: {reason}")
        self.job_id  = job_id
        self.reason  = reason
