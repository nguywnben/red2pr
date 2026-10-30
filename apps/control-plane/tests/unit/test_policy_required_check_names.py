from py_contracts.integrations import RepositoryPolicy
from red2pr_control.repositories.policy_engine import compute_policy_rule_changes


def _policy(names: list[str]) -> RepositoryPolicy:
    return RepositoryPolicy(
        required_check_names=names,
        runtime_profile_id="python-3.12-isolated",
    )


def test_adding_required_remote_check_is_versioned_without_weakening_step_up() -> None:
    changes, requires_step_up = compute_policy_rule_changes(
        current_mode="approval",
        current_paused=False,
        current_policy=_policy([]),
        target_mode="approval",
        target_paused=False,
        target_policy=_policy(["build"]),
    )

    assert any(change.field == "required_check_names" for change in changes)
    assert requires_step_up is False


def test_removing_required_remote_check_requires_fresh_step_up() -> None:
    changes, requires_step_up = compute_policy_rule_changes(
        current_mode="approval",
        current_paused=False,
        current_policy=_policy(["build", "tests"]),
        target_mode="approval",
        target_paused=False,
        target_policy=_policy(["build"]),
    )

    change = next(change for change in changes if change.field == "required_check_names")
    assert change.requires_step_up is True
    assert requires_step_up is True
