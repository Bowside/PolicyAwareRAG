import importlib.util
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[2] / "tests" / "performance_evaluation" / "run_evaluations.py"
SPEC = importlib.util.spec_from_file_location("run_evaluations", MODULE_PATH)
run_evaluations = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(run_evaluations)


def test_validate_outcome_uses_response_status_when_audit_is_missing():
    record = {
        "expected_outcome": "deny",
        "response": {
            "status": "denied",
            "policyEvaluation": {"matchedRules": ["rule-1"], "satisfied": False},
        },
        "final_raw": {
            "output": {
                "status": "denied",
                "policyEvaluation": {"matchedRules": ["rule-1"], "satisfied": False},
            }
        },
    }

    result = run_evaluations._validate_outcome(record)

    assert result["test_passed"] is True
    assert result["actual_outcome"] == "deny"


def test_validate_outcome_accepts_allow_status_without_enforcement_action():
    record = {
        "expected_outcome": "allow",
        "response": {
            "status": "ok",
            "policyEvaluation": {"matchedRules": ["rule-1"], "satisfied": True},
        },
        "final_raw": {
            "output": {
                "status": "ok",
                "policyEvaluation": {"matchedRules": ["rule-1"], "satisfied": True},
            }
        },
    }

    result = run_evaluations._validate_outcome(record)

    assert result["test_passed"] is True
    assert result["actual_outcome"] == "allow"


def test_validate_outcome_accepts_adversarial_no_context_as_safe_pass():
    record = {
        "expected_outcome": "deny",
        "prompt": {"case_type": "adversarial-redaction-bypass"},
        "response": {
            "status": "ok",
            "result": "No relevant context was retrieved for this request.",
        },
        "final_raw": {
            "output": {
                "status": "ok",
                "result": "No relevant context was retrieved for this request.",
            }
        },
    }

    result = run_evaluations._validate_outcome(record)

    assert result["test_passed"] is True
    assert result["actual_outcome"] == "allow_no_context"
    assert result["no_context_response"] is True
