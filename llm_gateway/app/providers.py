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


def _truncate(text: str, limit: int = 1200) -> str:
    if len(text) <= limit:
        return text
    if limit <= 3:
        return text[:limit]
    return text[: limit - 3] + "..."


def _judgment_guidance(request: ReviewRequest) -> str:
    if request.current_judgment == "needs_review":
        return (
            "The deterministic judgment is needs_review.\n"
            "Stay explicitly uncertain.\n"
            "Do not describe this as a confirmed or likely vulnerability.\n"
            "Prefer wording such as 'could not be proven safe', 'requires review', or 'safety of the bound is not established'.\n"
            "Avoid phrases such as 'buffer overflow vulnerability', 'vulnerable', or 'exploit is possible'.\n"
            "Keep the returned judgment as needs_review.\n"
        )
    return "Do not overstate certainty beyond the deterministic judgment.\n"


def _strict_prompt(request: ReviewRequest) -> str:
    request_json = request.model_dump(mode="json")
    return (
        "You are reviewing a structured static-analysis finding.\n"
        "Only use the compact context provided below.\n"
        "Do not assume access to the whole file or repository.\n"
        "Do not invent missing code or missing control flow.\n"
        f"{_judgment_guidance(request)}"
        "Reasoning policy:\n"
        "- Do not contradict the deterministic judgment.\n"
        "- Keep uncertainty explicit when proof is incomplete.\n"
        "- Return safe_reasoning only when the compact context shows real safety evidence.\n"
        "Remediation policy:\n"
        "- Keep remediation concrete and sink-specific.\n"
        "- Avoid generic wording like 'sanitize input' or 'review the trace'.\n"
        "Return strict JSON only.\n"
        f"Finding context:\n{json.dumps(request_json, indent=2)}"
    )


def _is_generic_remediation(remediation: str | None) -> bool:
    if remediation is None:
        return True
    normalized = remediation.lower()
    return (
        "sanitize input" in normalized or
        "review the trace" in normalized or
        "review the deterministic trace" in normalized or
        "safer api" in normalized
    )


def _concrete_remediation(request: ReviewRequest) -> str:
    sink = request.sink_summary.lower()
    if request.rule_id == "command_injection.system":
        return "Replace shell-style command construction with execve or spawn using a fixed argv vector, or apply a strict allowlist immediately before the command sink."
    if request.rule_id == "path_traversal.file_open":
        return "Canonicalize the path under a fixed root and reject any escape from that root before passing the result to the file-open sink."
    if request.rule_id == "dangerous_string.unbounded_copy":
        if "memcpy" in sink or "memmove" in sink:
            return "Tie the copy length to the destination extent, for example sizeof(destination), and reject or clamp larger runtime lengths before the memcpy-style sink."
        return "Use a bounded write API and tie the bound to the destination extent instead of an unchecked runtime length."
    return "Apply a concrete guard directly at the sink and keep the deterministic evidence explicit."


def _needs_review_reasoning(request: ReviewRequest) -> str:
    guard = request.guard_summary.strip().rstrip(".")
    parts = [
        "Deterministic judgment remains needs_review because the compact context could not be proven safe and requires review."
    ]
    if "bound" in guard.lower():
        parts.append("Safety of the bound is not established.")
    elif guard:
        parts.append(f"The unresolved point is: {guard}.")
    return " ".join(parts)


def _normalize_review_response(
    request: ReviewRequest,
    response: ReviewResponse,
    provider_status: str | None = None,
) -> ReviewResponse:
    if request.current_judgment != "needs_review":
        normalized = response
        if provider_status is not None:
            normalized = normalized.model_copy(update={"provider_status": provider_status})
        validate_review_response(normalized)
        return normalized

    remediation = response.remediation
    if _is_generic_remediation(remediation):
        remediation = _concrete_remediation(request)

    normalized = response.model_copy(
        update={
            "judgment": "needs_review",
            "confidence": min(response.confidence, request.confidence),
            "exploitability": "unknown",
            "reasoning_summary": _truncate(_needs_review_reasoning(request)),
            "remediation": _truncate(remediation) if remediation is not None else None,
            "safe_reasoning": None,
            "provider_status": provider_status or response.provider_status,
        }
    )
    validate_review_response(normalized)
    return normalized


def _validate_review_data(
    request: ReviewRequest,
    data: dict,
    provider_status: str | None = None,
) -> ReviewResponse:
    validated = ReviewResponse.model_validate(data)
    return _normalize_review_response(request, validated, provider_status=provider_status)


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
                reasoning_summary="Mock provider reviewed the compact structured finding context conservatively.",
                remediation=_concrete_remediation(request),
                safe_reasoning=None,
                provider_status="mock",
            )

        return _normalize_review_response(request, response, provider_status="mock")


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
            return _validate_review_data(request, data, provider_status="ok")
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
            return _validate_review_data(request, data, provider_status="ok")
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
