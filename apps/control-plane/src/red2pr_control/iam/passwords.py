"""Argon2id password hashing, password policy enforcement & anti-enumeration dummy verify.

Implements docs/14_SECURITY_IDENTITY.md, UX-LOGIN-001, and SEC-026:
- RFC 9106 / OWASP Argon2id hashing (`memory_cost=65536 KiB`, `time_cost=3`, `parallelism=4`).
- Minimum 12-character, maximum 256-character password policy rejecting control characters,
  blank strings, single-character repetition, and identity-echo passwords.
- Constant-work dummy Argon2id verification when account lookup misses or account is
  disabled so timing side channels cannot enumerate valid identifiers.
"""

from __future__ import annotations

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from py_contracts.primitives import ProblemFieldError
from red2pr_control.core.errors import UnprocessableEntityError

MIN_PASSWORD_LENGTH: int = 12
MAX_PASSWORD_LENGTH: int = 256

_DEFAULT_HASHER = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)

# Precomputed once at import time so unknown-account logins execute identical Argon2id work.
_DUMMY_ARGON2ID_HASH: str = _DEFAULT_HASHER.hash("red2pr-dummy-anti-enumeration-secret-v1")


def validate_new_password_policy(
    password: str,
    *,
    disallowed_substrings: tuple[str, ...] = (),
    field_name: str = "password",
) -> None:
    """Enforce deterministic password strength bounds before Argon2id hashing."""
    if len(password) < MIN_PASSWORD_LENGTH or len(password) > MAX_PASSWORD_LENGTH:
        raise UnprocessableEntityError(
            code="weak_password",
            detail=(
                f"Password must be between {MIN_PASSWORD_LENGTH} and {MAX_PASSWORD_LENGTH} "
                "characters."
            ),
            errors=[ProblemFieldError(field=field_name, code="password_length")],
        )
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in password):
        raise UnprocessableEntityError(
            code="weak_password",
            detail="Password must not contain control characters.",
            errors=[ProblemFieldError(field=field_name, code="password_control_chars")],
        )
    if not password.strip() or len(set(password)) < 4:
        raise UnprocessableEntityError(
            code="weak_password",
            detail="Password must contain sufficient character variety.",
            errors=[ProblemFieldError(field=field_name, code="password_low_entropy")],
        )

    lowered_pw = password.lower()
    for token in disallowed_substrings:
        cleaned = token.strip().lower()
        if len(cleaned) >= 4 and cleaned in lowered_pw:
            raise UnprocessableEntityError(
                code="weak_password",
                detail="Password must not contain your account identifier or display name.",
                errors=[ProblemFieldError(field=field_name, code="password_contains_identity")],
            )


def hash_password(password: str, *, hasher: PasswordHasher = _DEFAULT_HASHER) -> str:
    """Hash a plaintext password using Argon2id."""
    return hasher.hash(password)


def verify_password_and_check_rehash(
    password_hash: str,
    candidate_password: str,
    *,
    hasher: PasswordHasher = _DEFAULT_HASHER,
) -> tuple[bool, bool]:
    """Verify `candidate_password` against `password_hash`, returning `(ok, needs_rehash)`."""
    try:
        hasher.verify(password_hash, candidate_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False, False
    return True, bool(hasher.check_needs_rehash(password_hash))


def verify_dummy_password(
    candidate_password: str,
    *,
    hasher: PasswordHasher = _DEFAULT_HASHER,
) -> None:
    """Execute full Argon2id work when user lookup misses to defeat timing enumeration."""
    try:
        hasher.verify(_DUMMY_ARGON2ID_HASH, candidate_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return
