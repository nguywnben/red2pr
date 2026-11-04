import pytest

from red2pr_control.core.errors import ConflictError
from red2pr_control.publisher.patch_apply import apply_verified_unified_diff
from red2pr_control.publisher.saga import (
    _safe_review_url,
    deterministic_branch,
    deterministic_marker,
)


def test_apply_verified_patch_updates_and_creates_regular_text_files() -> None:
    diff = """diff --git a/src/fix.py b/src/fix.py
--- a/src/fix.py
+++ b/src/fix.py
@@ -1,2 +1,2 @@
 return old()
-raise RuntimeError()
+return new()
diff --git a/src/new.py b/src/new.py
new file mode 100644
--- /dev/null
+++ b/src/new.py
@@ -0,0 +1 @@
+print('new')
"""
    assert apply_verified_unified_diff(
        diff,
        base_contents={"src/fix.py": "return old()\nraise RuntimeError()\n", "src/new.py": None},
    ) == {"src/fix.py": "return old()\nreturn new()\n", "src/new.py": "print('new')\n"}


def test_apply_verified_patch_deletes_file_and_rejects_wrong_base_context() -> None:
    deletion = """diff --git a/src/old.py b/src/old.py
deleted file mode 100644
--- a/src/old.py
+++ /dev/null
@@ -1 +0,0 @@
-old()
"""
    assert apply_verified_unified_diff(deletion, base_contents={"src/old.py": "old()\n"}) == {
        "src/old.py": None
    }
    with pytest.raises(ConflictError, match="base revision"):
        apply_verified_unified_diff(
            deletion,
            base_contents={"src/old.py": "different()\n"},
        )


def test_apply_verified_patch_recounts_hunk_lengths_when_base_lines_match_exact() -> None:
    base = (
        "from decimal import Decimal, ROUND_HALF_UP\n"
        "\n"
        'ZERO_DECIMAL_CURRENCIES = frozenset({"JPY", "KRW", "VND"})\n'
        'THREE_DECIMAL_CURRENCIES = frozenset({"KWD", "BHD", "OMR"})\n'
        "def quantize_minor_units(amount: Decimal, currency: str) -> Decimal:\n"
        "    code = currency.upper().strip()\n"
        "    if code in THREE_DECIMAL_CURRENCIES:\n"
        '        exponent = Decimal("0.001")\n'
        "    else:\n"
        '        exponent = Decimal("0.01")\n'
        "    return amount.quantize(exponent, rounding=ROUND_HALF_UP)\n"
    )
    # Model declared -3,7 +3,9 even though body contains 8 old and 10 new lines.
    diff = (
        "--- a/src/payments/rounding.py\n"
        "+++ b/src/payments/rounding.py\n"
        "@@ -3,7 +3,9 @@\n"
        ' ZERO_DECIMAL_CURRENCIES = frozenset({"JPY", "KRW", "VND"})\n'
        ' THREE_DECIMAL_CURRENCIES = frozenset({"KWD", "BHD", "OMR"})\n'
        " def quantize_minor_units(amount: Decimal, currency: str) -> Decimal:\n"
        "     code = currency.upper().strip()\n"
        "-    if code in THREE_DECIMAL_CURRENCIES:\n"
        "+    if code in ZERO_DECIMAL_CURRENCIES:\n"
        '+        exponent = Decimal("1")\n'
        "+    elif code in THREE_DECIMAL_CURRENCIES:\n"
        '         exponent = Decimal("0.001")\n'
        "     else:\n"
        '         exponent = Decimal("0.01")\n'
    )
    updated = apply_verified_unified_diff(diff, base_contents={"src/payments/rounding.py": base})
    assert updated["src/payments/rounding.py"] == (
        "from decimal import Decimal, ROUND_HALF_UP\n"
        "\n"
        'ZERO_DECIMAL_CURRENCIES = frozenset({"JPY", "KRW", "VND"})\n'
        'THREE_DECIMAL_CURRENCIES = frozenset({"KWD", "BHD", "OMR"})\n'
        "def quantize_minor_units(amount: Decimal, currency: str) -> Decimal:\n"
        "    code = currency.upper().strip()\n"
        "    if code in ZERO_DECIMAL_CURRENCIES:\n"
        '        exponent = Decimal("1")\n'
        "    elif code in THREE_DECIMAL_CURRENCIES:\n"
        '        exponent = Decimal("0.001")\n'
        "    else:\n"
        '        exponent = Decimal("0.01")\n'
        "    return amount.quantize(exponent, rounding=ROUND_HALF_UP)\n"
    )

    empty_hunk = "--- a/src/payments/rounding.py\n+++ b/src/payments/rounding.py\n@@ -1,1 +1,1 @@\n"
    with pytest.raises(ConflictError):
        apply_verified_unified_diff(empty_hunk, base_contents={"src/payments/rounding.py": base})


@pytest.mark.parametrize(
    "diff",
    [
        "--- a/../escape.py\n+++ b/../escape.py\n@@ -1 +1 @@\n-a\n+b\n",
        "--- a/file.py\n+++ b/other.py\n@@ -1 +1 @@\n-a\n+b\n",
        "GIT binary patch\n",
    ],
)
def test_apply_verified_patch_rejects_unsafe_or_unsupported_inputs(diff: str) -> None:
    with pytest.raises(ConflictError):
        apply_verified_unified_diff(diff, base_contents={"safe.py": "a\n"})


def test_publication_markers_and_branch_are_deterministic_and_bound_to_repair_effect() -> None:
    run_id = "0196f000-0000-7000-8000-000000000001"
    repair_id = "0196f000-0000-7000-8000-000000000002"
    patch_digest = "a" * 64
    branch = deterministic_branch(run_id, repair_id, patch_digest)
    assert branch.startswith(f"red2pr/{run_id}/")
    assert branch == deterministic_branch(run_id, repair_id, patch_digest)
    assert branch != deterministic_branch(run_id, repair_id, "b" * 64)
    assert deterministic_marker(repair_id, "github", patch_digest) == deterministic_marker(
        repair_id, "github", patch_digest
    )


def test_provider_review_urls_must_be_https_and_strip_query_secrets() -> None:
    assert _safe_review_url("https://github.com/acme/repo/pull/1?token=secret#diff") == (
        "https://github.com/acme/repo/pull/1"
    )
    with pytest.raises(ConflictError):
        _safe_review_url("http://github.com/acme/repo/pull/1")
