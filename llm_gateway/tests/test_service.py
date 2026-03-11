import asyncio

from llm_gateway.app.providers import BaseProvider, MockProvider, ProviderError
from llm_gateway.app.schemas import ReviewRequest, ReviewResponse
from llm_gateway.app.service import ReviewService
from llm_gateway.app.settings import GatewaySettings


class FlakyProvider(BaseProvider):
    def __init__(self, failures_before_success: int) -> None:
        self.failures_before_success = failures_before_success
        self.calls = 0

    async def review(self, request: ReviewRequest) -> ReviewResponse:
        self.calls += 1
        if self.calls <= self.failures_before_success:
            raise ProviderError("temporary failure")
        return ReviewResponse(
            judgment="likely_issue",
            confidence=0.83,
            cwe="CWE-78",
            exploitability="medium",
            reasoning_summary="Provider reviewed the ambiguous finding after retry.",
            remediation="Prefer fixed argv execution.",
            safe_reasoning=None,
            provider_status="ok",
        )


class FailingProvider(BaseProvider):
    def __init__(self) -> None:
        self.calls = 0

    async def review(self, request: ReviewRequest) -> ReviewResponse:
        self.calls += 1
        raise ProviderError("network failure")


def sample_request(
    judgment: str = "needs_review",
    severity: str = "high",
) -> ReviewRequest:
    return ReviewRequest.model_validate(
        {
            "candidate_id": "cand-1",
            "rule_id": "command_injection.system",
            "current_judgment": judgment,
            "provisional_severity": severity,
            "confidence": 0.64,
            "source_summary": "argv[1]",
            "sink_summary": "system(cmd)",
            "path_summary": "argv[1] -> cmd -> system",
            "guard_summary": "no guard",
            "code_windows": [
                {
                    "file_path": "demo.cpp",
                    "start_line": 10,
                    "end_line": 12,
                    "snippet": "const char* cmd = argv[1];\nsystem(cmd);",
                }
            ],
        }
    )


def test_service_routes_to_mock_provider() -> None:
    settings = GatewaySettings(provider="mock", api_key="unused", max_retries=1)
    service = ReviewService(MockProvider(settings), settings)
    response = asyncio.run(service.review(sample_request()))
    assert response.provider_status == "mock"
    assert response.judgment == "needs_review"


def test_service_retries_then_succeeds() -> None:
    provider = FlakyProvider(failures_before_success=1)
    service = ReviewService(provider, GatewaySettings(api_key="unused", max_retries=2))
    response = asyncio.run(service.review(sample_request()))
    assert provider.calls == 2
    assert response.provider_status == "ok"
    assert response.judgment == "likely_issue"


def test_service_falls_back_when_provider_fails() -> None:
    provider = FailingProvider()
    service = ReviewService(provider, GatewaySettings(api_key="unused", max_retries=2))
    response = asyncio.run(service.review(sample_request()))
    assert provider.calls == 2
    assert response.provider_status == "fallback"
    assert response.judgment == "needs_review"
    assert "LLM review unavailable" in response.reasoning_summary


def test_service_routes_likely_safe_when_proof_is_incomplete() -> None:
    settings = GatewaySettings(provider="mock", api_key="unused", max_retries=1)
    service = ReviewService(MockProvider(settings), settings)
    request = sample_request("likely_safe", "low")
    response = asyncio.run(service.review(request))
    assert response.provider_status == "mock"
    assert response.judgment == "likely_safe"
    assert response.safe_reasoning is not None


def test_service_can_disable_review_by_configuration() -> None:
    settings = GatewaySettings(enabled=False, provider="mock", api_key="unused", max_retries=1)
    service = ReviewService(MockProvider(settings), settings)
    request = sample_request("needs_review", "high")
    response = asyncio.run(service.review(request))
    assert response.provider_status == "fallback"
    assert "disabled by configuration" in response.reasoning_summary


def test_service_does_not_route_confirmed_issue() -> None:
    settings = GatewaySettings(provider="mock", api_key="unused", max_retries=1)
    service = ReviewService(MockProvider(settings), settings)
    response = asyncio.run(service.review(sample_request("confirmed_issue", "critical")))
    assert response.provider_status == "fallback"
    assert "routing policy" in response.reasoning_summary
