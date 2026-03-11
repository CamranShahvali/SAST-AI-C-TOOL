from __future__ import annotations

import abc
import json

import httpx
from jsonschema import ValidationError as JsonSchemaValidationError
from pydantic import ValidationError as PydanticValidationError

from .schemas import ReviewRequest, ReviewResponse
from .settings import GatewaySettings
from .validation import validate_review_request, validate_review_response


class ProviderError(RuntimeError):
    pass


class BaseProvider(abc.ABC):
    @abc.abstractmethod
    async def review(self, request: ReviewRequest) -> ReviewResponse:
        raise NotImplementedError


def _strict_prompt(request: ReviewRequest) -> str:
    request_json = request.model_dump(mode="json")
    return (
        "You are reviewing a structured static-analysis finding.\n"
        "Only use the compact context provided below.\n"
        "Do not assume access to the whole file or repository.\n"
        "Do not invent missing code or missing control flow.\n"
        "Return strict JSON only.\n"
        f"Finding context:\n{json.dumps(request_json, indent=2)}"
    )


def _validate_review_data(data: dict, provider_status: str | None = None) -> ReviewResponse:
    validated = ReviewResponse.model_validate(data)
    if provider_status is not None:
        validated = validated.model_copy(update={"provider_status": provider_status})
    validate_review_response(validated)
    return validated


class MockProvider(BaseProvider):
    _cwe_by_rule = {
        "command_injection.system": "CWE-78",
        "path_traversal.file_open": "CWE-22",
        "dangerous_string.unbounded_copy": "CWE-120",
    }

    def __init__(self, settings: GatewaySettings) -> None:
        self._settings = settings

    async def review(self, request: ReviewRequest) -> ReviewResponse:
        validate_review_request(request)

        if request.current_judgment in {"likely_safe", "safe_suppressed"}:
            response = ReviewResponse(
                judgment=request.current_judgment,
                confidence=max(request.confidence, 0.92),
                cwe=self._cwe_by_rule.get(request.rule_id),
                exploitability="low",
                reasoning_summary="Mock provider retained the deterministic safety assessment.",
                remediation="No additional remediation required beyond the deterministic safety barrier.",
                safe_reasoning="Mock review agrees that the deterministic engine already established a safety barrier.",
                provider_status="mock",
            )
        else:
            response = ReviewResponse(
                judgment=request.current_judgment,
                confidence=max(request.confidence, 0.74),
                cwe=self._cwe_by_rule.get(request.rule_id),
                exploitability="medium" if request.provisional_severity in {"high", "critical"} else "low",
                reasoning_summary="Mock provider reviewed the compact structured finding context.",
                remediation="Review the deterministic trace and replace risky sinks with constrained APIs or fixed arguments.",
                safe_reasoning=None,
                provider_status="mock",
            )

        validate_review_response(response)
        return response


class OpenAIResponsesProvider(BaseProvider):
    def __init__(
        self,
        settings: GatewaySettings,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._settings = settings
        self._transport = transport

    def _response_payload(self, request: ReviewRequest) -> dict:
        validate_review_request(request)
        return {
            "model": self._settings.model,
            "input": _strict_prompt(request),
            "text": {
                "format": {
                    "type": "json_schema",
                    "name": "sast_review",
                    "schema": ReviewResponse.model_json_schema(),
                    "strict": True,
                }
            },
        }

    def _extract_response_json(self, payload: dict) -> dict:
        if isinstance(payload.get("output_text"), str):
            return json.loads(payload["output_text"])
        for item in payload.get("output", []):
            for content in item.get("content", []):
                if content.get("type") == "output_text" and isinstance(content.get("text"), str):
                    return json.loads(content["text"])
        raise ProviderError("provider response did not contain structured JSON")

    async def review(self, request: ReviewRequest) -> ReviewResponse:
        validate_review_request(request)
        if not self._settings.api_key:
            raise ProviderError("OPENAI_API_KEY is not configured")

        headers = {
            "Authorization": f"Bearer {self._settings.api_key}",
            "Content-Type": "application/json",
        }
        try:
            async with httpx.AsyncClient(
                timeout=self._settings.timeout_seconds,
                transport=self._transport,
            ) as client:
                response = await client.post(
                    f"{self._settings.base_url.rstrip('/')}/v1/responses",
                    headers=headers,
                    json=self._response_payload(request),
                )
                response.raise_for_status()
        except (httpx.TimeoutException, httpx.HTTPError) as exc:
            raise ProviderError(f"provider request failed: {exc}") from exc

        try:
            data = self._extract_response_json(response.json())
            return _validate_review_data(data, provider_status="ok")
        except (
            json.JSONDecodeError,
            JsonSchemaValidationError,
            PydanticValidationError,
            ValueError,
        ) as exc:
            raise ProviderError(f"provider returned invalid structured JSON: {exc}") from exc


class OllamaProvider(BaseProvider):
    def __init__(
        self,
        settings: GatewaySettings,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._settings = settings
        self._transport = transport

    def _response_payload(self, request: ReviewRequest) -> dict:
        validate_review_request(request)
        return {
            "model": self._settings.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You review compact static-analysis findings. "
                        "You must return strict JSON that matches the provided schema."
                    ),
                },
                {
                    "role": "user",
                    "content": _strict_prompt(request),
                },
            ],
            "stream": False,
            "format": ReviewResponse.model_json_schema(),
            "options": {
                "temperature": 0,
            },
        }

    def _extract_response_json(self, payload: dict) -> dict:
        if (
            isinstance(payload.get("message"), dict) and
            isinstance(payload["message"].get("content"), str)
        ):
            return json.loads(payload["message"]["content"])
        raise ProviderError("provider response did not contain structured JSON")

    async def review(self, request: ReviewRequest) -> ReviewResponse:
        validate_review_request(request)

        try:
            async with httpx.AsyncClient(
                timeout=self._settings.timeout_seconds,
                transport=self._transport,
            ) as client:
                response = await client.post(
                    f"{self._settings.base_url.rstrip('/')}/api/chat",
                    json=self._response_payload(request),
                )
                response.raise_for_status()
        except (httpx.TimeoutException, httpx.HTTPError) as exc:
            raise ProviderError(f"provider request failed: {exc}") from exc

        try:
            data = self._extract_response_json(response.json())
            return _validate_review_data(data, provider_status="ok")
        except (
            json.JSONDecodeError,
            JsonSchemaValidationError,
            PydanticValidationError,
            ValueError,
        ) as exc:
            raise ProviderError(f"provider returned invalid structured JSON: {exc}") from exc


def create_provider(settings: GatewaySettings) -> BaseProvider:
    if settings.provider == "mock":
        return MockProvider(settings)
    if settings.provider == "ollama":
        return OllamaProvider(settings)
    if settings.provider == "openai_responses":
        return OpenAIResponsesProvider(settings)
    raise ValueError(f"unsupported llm provider: {settings.provider}")
