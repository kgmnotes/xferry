"""One portable generated-access policy for every deployment backend."""

from __future__ import annotations

import secrets

PASSWORD_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"


def generate_password() -> str:
    """Return a twelve-character password without ambiguous characters."""
    return "".join(secrets.choice(PASSWORD_ALPHABET) for _ in range(12))
