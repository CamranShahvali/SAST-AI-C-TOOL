from jsonschema import Draft202012Validator
import pytest

from llm_gateway.app.schemas import (
    REQUEST_JSON_SCHEMA,
    RESPONSE_JSON_SCHEMA,
    ReviewRequest,
    ReviewResponse,
)


def sample_request_payload() -> dict:
    return {
        "candidate_id": "cand-1",
        "rule_id": "command_injection.system",
        "current_judgment": "needs_review",
        "provisional_severity": "high",
        "confidence": 0.61,
        "source_summary": "argv[1]",
        "sink_summary": "system(cmd)",
        "path_summary": "argv[1] -> cmd -> system",
        "guard_summary": "no strict allowlist proved",
        "code_windows": [
            {
                "file_path": "demo.cpp",
                "start_line": 10,
                "end_line": 14,
                "snippet": "const char* cmd = argv[1];\nsystem(cmd);",
            }
        ],
    }


def test_request_schema_is_valid_json_schema() -> None:
    Draft202012Validator.check_schema(REQUEST_JSON_SCHEMA)


def test_response_schema_is_valid_json_schema() -> None:
    Draft202012Validator.check_schema(RESPONSE_JSON_SCHEMA)


def test_request_rejects_more_than_two_windows() -> None:
    payload = sample_request_payload()
    payload["code_windows"] = [
        {"file_path": "a.cpp", "start_line": 1, "end_line": 2, "snippet": "a"},
        {"file_path": "b.cpp", "start_line": 1, "end_line": 2, "snippet": "b"},
        {"file_path": "c.cpp", "start_line": 1, "end_line": 2, "snippet": "c"},
    ]
    with pytest.raises(Exception):
        ReviewRequest.model_validate(payload)


def test_request_rejects_window_larger_than_twelve_lines() -> None:
    payload = sample_request_payload()
    payload["code_windows"][0]["end_line"] = 25
    with pytest.raises(Exception):
        ReviewRequest.model_validate(payload)


def test_response_requires_reasoning_summary() -> None:
    response = ReviewResponse.model_validate(
        {
            "judgment": "likely_issue",
            "confidence": 0.7,
            "cwe": "CWE-78",
            "exploitability": "medium",
            "reasoning_summary": "Shell execution remains reachable from user input.",
            "remediation": "Use execve with fixed argv.",
            "safe_reasoning": None,
            "provider_status": "ok",
        }
    )
    assert response.judgment == "likely_issue"
