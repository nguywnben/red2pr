from red2pr_control.integrations.base import ProviderRemoteCheckRecord
from red2pr_control.publisher.remote_observer import evaluate_required_checks


def check(
    name: str, *, sha: str = "a" * 40, status: str = "completed", conclusion: str = "success"
):
    return ProviderRemoteCheckRecord(
        external_check_id=f"id-{name}",
        name=name,
        head_sha=sha,
        status=status,
        conclusion=conclusion,
    )


def test_required_checks_pass_only_on_exact_sha():
    verdict = evaluate_required_checks(
        expected_sha="a" * 40,
        required_names=("build", "tests"),
        checks=(check("build"), check("tests")),
    )
    assert verdict.outcome == "passed"


def test_missing_and_wrong_sha_required_checks_remain_pending():
    verdict = evaluate_required_checks(
        expected_sha="a" * 40,
        required_names=("build", "tests"),
        checks=(check("build", sha="b" * 40),),
    )
    assert verdict.outcome == "pending"
    assert verdict.missing_required == ("tests",)
    assert verdict.wrong_sha_required == ("build",)


def test_skipped_neutral_failed_and_empty_required_sets_never_go_green():
    skipped = evaluate_required_checks(
        expected_sha="a" * 40,
        required_names=("build",),
        checks=(check("build", conclusion="skipped"),),
    )
    assert skipped.outcome == "failed"
    neutral = evaluate_required_checks(
        expected_sha="a" * 40,
        required_names=("build",),
        checks=(check("build", conclusion="neutral"),),
    )
    assert neutral.outcome == "failed"
    failed = evaluate_required_checks(
        expected_sha="a" * 40,
        required_names=("build",),
        checks=(check("build", conclusion="failure"),),
    )
    assert failed.outcome == "failed"
    empty = evaluate_required_checks(expected_sha="a" * 40, required_names=(), checks=())
    assert empty.outcome == "unknown"


def test_in_progress_duplicate_prevents_pass_even_if_other_attempt_is_green():
    verdict = evaluate_required_checks(
        expected_sha="a" * 40,
        required_names=("build",),
        checks=(check("build"), check("build", status="in_progress", conclusion="success")),
    )
    assert verdict.outcome == "pending"
