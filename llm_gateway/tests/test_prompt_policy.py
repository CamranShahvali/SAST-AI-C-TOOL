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


def sample_request_for(judgment: str, rule_id: str, sink_summary: str, guard_summary: str) -> ReviewRequest:
    request = sample_request().model_copy(
        update={
            "current_judgment": judgment,
            "rule_id": rule_id,
            "sink_summary": sink_summary,
            "guard_summary": guard_summary,
        }
    )
    return ReviewRequest.model_validate(request.model_dump(mode="json"))


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


def test_prompt_guidance_keeps_likely_issue_below_confirmed() -> None:
    prompt = _strict_prompt(
        sample_request_for(
            "likely_issue",
            "path_traversal.file_open",
            'fopen(normalize_path(argv[1]), "r")',
            "path validation wrapper is not modeled",
        )
    )

    assert "The deterministic judgment is likely_issue." in prompt
    assert "Keep the result below confirmed_issue." in prompt
    assert "proof is still incomplete" in prompt


def test_prompt_guidance_keeps_likely_safe_cautious() -> None:
    prompt = _strict_prompt(
        sample_request_for(
            "likely_safe",
            "path_traversal.file_open",
            'fopen(path.c_str(), "r")',
            "path allowlist exists but root confinement proof is incomplete",
        )
    )

    assert "The deterministic judgment is likely_safe." in prompt
    assert "Do not frame this as a real vulnerability." in prompt
    assert "proof more explicit at the sink" in prompt


def test_likely_issue_remediation_stays_sink_specific() -> None:
    request = sample_request_for(
        "likely_issue",
        "command_injection.system",
        "system(cmd)",
        "no allowlist proved",
    )
    response = ReviewResponse(
        judgment="likely_issue",
        confidence=0.77,
        cwe="CWE-78",
        exploitability="medium",
        reasoning_summary="Risk remains elevated.",
        remediation="sanitize input",
        safe_reasoning=None,
        provider_status="ok",
    )

    normalized = _normalize_review_response(request, response, provider_status="ok")

    assert normalized.judgment == "likely_issue"
    assert normalized.remediation is not None
    assert "fixed argv vector" in normalized.remediation.lower()
    assert "allowlist" in normalized.remediation.lower()


def test_likely_safe_remediation_stays_cautious_and_concrete() -> None:
    request = sample_request_for(
        "likely_safe",
        "path_traversal.file_open",
        'fopen(path.c_str(), "r")',
        "path allowlist predicate constrains user input",
    )
    response = ReviewResponse(
        judgment="likely_safe",
        confidence=0.79,
        cwe="CWE-22",
        exploitability="low",
        reasoning_summary="Safety evidence exists but proof is incomplete.",
        remediation="No additional remediation required beyond the deterministic safety barrier.",
        safe_reasoning="Input is filtered first.",
        provider_status="ok",
    )

    normalized = _normalize_review_response(request, response, provider_status="ok")

    assert normalized.judgment == "likely_safe"
    assert normalized.remediation is not None
    assert "provably safe" in normalized.remediation.lower()
    assert "fixed trusted root" in normalized.remediation.lower()
    assert "no additional remediation required" not in normalized.remediation.lower()
