"""
utils/auth.py — Synthegria API key registry

Maps simple API keys to Stripe Customer IDs.
In production this would live in a database; here it's a hardcoded dict
for local testing.
"""

# ---------------------------------------------------------------------------
# Key → Stripe Customer ID mapping
# ---------------------------------------------------------------------------

API_KEY_MAP: dict[str, str] = {
    "synthegria_test_key_1": "cus_UZ7oQ2QGGb7PjN",   # Tenant 1 — Synthegria SIEM Test
    "synthegria_test_key_2": "cus_UZGcWFCthk4shy",    # Tenant 2 — Synthegria SIEM Tenant 2
    "synthegria_test_key_3": "cus_PLACEHOLDER_3",      # reserved for future test tenant
}


class AuthError(Exception):
    """Raised when an API key is missing or unrecognised."""


def resolve_customer(api_key: str | None) -> str:
    """
    Resolve an API key to its Stripe Customer ID.

    Parameters
    ----------
    api_key : str | None
        The raw value from the X-API-Key header (or None if absent).

    Returns
    -------
    str
        The Stripe Customer ID associated with this key.

    Raises
    ------
    AuthError
        If the key is missing or not found in the registry.
    """
    if not api_key:
        raise AuthError("Missing API key — include X-API-Key in your request headers.")
    customer_id = API_KEY_MAP.get(api_key)
    if not customer_id:
        raise AuthError("Unknown or invalid API key.")
    return customer_id
