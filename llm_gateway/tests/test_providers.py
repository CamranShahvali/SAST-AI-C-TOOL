import asyncio
import json

import httpx
import pytest

from llm_gateway.app.providers import OpenAIResponsesProvider, ProviderError
from llm_gateway.app.schemas import ReviewRequest
from llm_gateway.app.settings import GatewaySettings


def sample_request() -> ReviewRequest:
    return ReviewRequest.model_validate(
        {
            "candidate_id": "cand-1",
            "rule_id": "command_injection.system",
            "current_judgment": "needs_review",
            "provisional_severity": "high",
            "confidence": 0.64,
            "source_summary": "argv[1]",
            "sink_summary": "system(cmd)",
            "path_summary": "argv[1] -> cmd -> system",
            "guard_summary": "no allowlist proved",
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


def settings() -> GatewaySettings:
    return GatewaySettings(
        enabled=True,
        provider="openai_responses",
        base_url="https://api.openai.com",
        api_key="test-key",
        model="gpt-5-mini",
        timeout_seconds=1.0,
        max_retries=2,
    )


def make_transport(handler):
    return httpx.MockTransport(handler)


def test_openai_provider_accepts_valid_structured_response() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/responses"
        body = json.loads(request.content.decode("utf-8"))
        assert body["model"] == "gpt-5-mini"
        assert body["text"]["format"]["type"] == "json_schema"
        assert body["text"]["format"]["strict"] is True
        payload = {
            "output_text": json.dumps(
                {
                    "judgment": "likely_issue",
                    "confidence": 0.83,
                    "cwe": "CWE-78",
                    "exploitability": "medium",
                    "reasoning_summary": "User input still reaches the sink.",
                    "remediation": "Use fixed argv execution.",
                    "safe_reasoning": None,
                    "provider_status": "ok",
                }
            )
        }
        return httpx.Response(200, json=payload)

    provider = OpenAIResponsesProvider(settings(), transport=make_transport(handler))
    response = asyncio.run(provider.review(sample_request()))

    assert response.judgment == "likely_issue"
    assert response.provider_status == "ok"


def test_openai_provider_rejects_invalid_schema_response() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        payload = {
            "output_text": json.dumps(
                {
                    "judgment": "bogus",
                    "confidence": 0.83,
                    "cwe": "CWE-78",
                    "exploitability": "medium",
                    "reasoning_summary": "bad schema",
                    "remediation": "Use fixed argv execution.",
                    "safe_reasoning": None,
                    "provider_status": "ok",
                }
            )
        }
        return httpx.Response(200, json=payload)

    provider = OpenAIResponsesProvider(settings(), transport=make_transport(handler))

    with pytest.raises(ProviderError, match="invalid structured JSON"):
        asyncio.run(provider.review(sample_request()))


def test_openai_provider_reports_timeout() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    provider = OpenAIResponsesProvider(settings(), transport=make_transport(handler))

    with pytest.raises(ProviderError, match="provider request failed"):
        asyncio.run(provider.review(sample_request()))


def test_openai_provider_rejects_malformed_output() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"output_text": "{not-json"})

    provider = OpenAIResponsesProvider(settings(), transport=make_transport(handler))

    with pytest.raises(ProviderError, match="invalid structured JSON"):
        asyncio.run(provider.review(sample_request()))
