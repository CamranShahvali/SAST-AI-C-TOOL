from llm_gateway.app.providers import _normalize_review_response, _strict_prompt
from llm_gateway.app.schemas import ReviewRequest, ReviewResponse


def sample_request() -> ReviewRequest:
    return ReviewRequest.model_validate(
        {
            "candidate_id": "cand-1",
            "rule_id": "dangerous_string.unbounded_copy",
            "current_judgment": "needs_review",
            "provisional_severity": "high",
            "confidence": 0.61,
            "source_summary": "argv[1]",
            "sink_summary": "memcpy(destination, argv[1], length)",
            "path_summary": "argv[1] -> destination",
            "guard_summary": "copy bound expression could not be proven against the destination extent",
            "code_windows": [
                {
                    "file_path": "demo.cpp",
                    "start_line": 12,
                    "end_line": 15,
                    "snippet": "char destination[8];\nstd::memcpy(destination, argv[1], length);",
                }
            ],
        }
    )


def test_prompt_keeps_needs_review_explicitly_uncertain() -> None:
    prompt = _strict_prompt(sample_request())
    assert "The deterministic judgment is needs_review." in prompt
    assert "Stay explicitly uncertain." in prompt
    assert "Do not describe this as a confirmed or likely vulnerability." in prompt
    assert "could not be proven safe" in prompt
    assert "safety of the bound is not established" in prompt


def test_needs_review_normalization_stays_neutral_and_uncertain() -> None:
    request = sample_request()
    response = ReviewResponse(
        judgment="likely_issue",
        confidence=0.92,
        cwe="CWE-120",
        exploitability="high",
        reasoning_summary="This is a buffer overflow vulnerability and exploit is possible.",
        remediation="sanitize input",
        safe_reasoning="looks safe enough",
        provider_status="ok",
    )

    normalized = _normalize_review_response(request, response, provider_status="ok")

    assert normalized.judgment == "needs_review"
    assert normalized.confidence == request.confidence
    assert normalized.exploitability == "unknown"
    assert "could not be proven safe" in normalized.reasoning_summary
    assert "requires review" in normalized.reasoning_summary
    assert "safety of the bound is not established" in normalized.reasoning_summary.lower()
    assert "buffer overflow vulnerability" not in normalized.reasoning_summary.lower()
    assert "vulnerable" not in normalized.reasoning_summary.lower()
    assert "exploit is possible" not in normalized.reasoning_summary.lower()


def test_needs_review_safe_reasoning_is_omitted_without_safety_evidence() -> None:
    request = sample_request()
    response = ReviewResponse(
        judgment="needs_review",
        confidence=0.5,
        cwe="CWE-120",
        exploitability="medium",
        reasoning_summary="Further analysis is needed.",
        remediation="Bind the copy length to sizeof(destination).",
        safe_reasoning="This path is safe.",
        provider_status="ok",
    )

    normalized = _normalize_review_response(request, response, provider_status="ok")

    assert normalized.safe_reasoning is None
    assert normalized.judgment == "needs_review"


def test_needs_review_remediation_stays_concrete_and_cautious() -> None:
    request = sample_request()
    response = ReviewResponse(
        judgment="needs_review",
        confidence=0.55,
        cwe="CWE-120",
        exploitability="medium",
        reasoning_summary="Need more review.",
        remediation="review the trace",
        safe_reasoning=None,
        provider_status="ok",
    )

    normalized = _normalize_review_response(request, response, provider_status="ok")

    assert normalized.remediation is not None
    assert "sizeof(destination)" in normalized.remediation
    assert "review the trace" not in normalized.remediation.lower()
