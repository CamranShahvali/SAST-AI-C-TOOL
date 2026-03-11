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
    if request.current_judgment == "likely_issue":
        return (
            "The deterministic judgment is likely_issue.\n"
            "Keep the result below confirmed_issue.\n"
            "Explain why the risk is real enough to escalate, but why proof is still incomplete.\n"
            "Do not describe this as fully confirmed or completely exploitable.\n"
        )
    if request.current_judgment == "likely_safe":
        return (
            "The deterministic judgment is likely_safe.\n"
            "Do not frame this as a real vulnerability.\n"
            "Explain that safety evidence exists, but the compact context does not yet prove a full safety barrier.\n"
            "Phrase any remediation as a way to make the safety proof more explicit at the sink.\n"
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
    if normalized.strip() in {"unknown", "n/a", "na", "none", "null"}:
        return True
    return (
        "sanitize input" in normalized or
        "review the trace" in normalized or
        "review the deterministic trace" in normalized or
        "safer api" in normalized or
        "no additional remediation required" in normalized
    )


def _split_guard_summary(request: ReviewRequest) -> tuple[str | None, str | None, str | None, str]:
    safe = None
    ambiguous = None
    positive = None
    fallback = request.guard_summary.strip().rstrip(".")

    for raw_part in request.guard_summary.split("|"):
        part = raw_part.strip().rstrip(".")
        normalized = part.lower()
        if normalized.startswith("safe:"):
            safe = part[5:].strip()
        elif normalized.startswith("ambiguous:"):
            ambiguous = part[10:].strip()
        elif normalized.startswith("positive:"):
            positive = part[9:].strip()

    return safe, ambiguous, positive, fallback


def _needs_review_remediation(request: ReviewRequest) -> str:
    sink = request.sink_summary.lower()
    if request.rule_id == "command_injection.system":
        return "Use a fixed argv vector or apply a strict allowlist immediately before the command sink."
    if request.rule_id == "path_traversal.file_open":
        return "Constrain the path under a fixed trusted root before the file-open sink and reject any escape from that root."
    if request.rule_id == "dangerous_string.unbounded_copy":
        if "memcpy" in sink or "memmove" in sink:
            return "Check the runtime length against the destination extent before the memcpy-style sink, or tie the bound directly to sizeof(destination)."
        return "Use a bounded write API and tie the bound directly to the destination extent."
    return "Add an explicit guard directly at the sink and keep the deterministic evidence visible."


def _likely_issue_remediation(request: ReviewRequest) -> str:
    sink = request.sink_summary.lower()
    if request.rule_id == "command_injection.system":
        return "Make the command path explicit with a fixed argv vector or a strict allowlist immediately before the command sink."
    if request.rule_id == "path_traversal.file_open":
        return "Constrain the path under a fixed trusted root immediately before the file-open sink and reject escapes from that root."
    if request.rule_id == "dangerous_string.unbounded_copy":
        if "memcpy" in sink or "memmove" in sink:
            return "Check the runtime length against the destination extent before the memcpy-style sink and reject larger values."
        return "Use a bounded write API and keep the bound adjacent to the destination extent."
    return "Make the missing guard explicit at the sink so the remaining proof gap is removed."


def _likely_safe_remediation(request: ReviewRequest) -> str:
    sink = request.sink_summary.lower()
    if request.rule_id == "command_injection.system":
        return "For a stronger safety proof, keep a fixed argv vector or place an explicit allowlist immediately before the command sink."
    if request.rule_id == "path_traversal.file_open":
        return "For a stronger safety proof, canonicalize the path under a fixed trusted root immediately before the file-open sink."
    if request.rule_id == "dangerous_string.unbounded_copy":
        if "memcpy" in sink or "memmove" in sink:
            return "For a stronger safety proof, check the runtime length against the destination extent and tie the copy bound directly to that extent before the memcpy-style sink."
        return "For a stronger safety proof, keep the bound adjacent to the destination extent and use a bounded write API."
    return "For a stronger safety proof, keep the safety guard explicit and adjacent to the sink."


def _preferred_remediation(request: ReviewRequest) -> str:
    if request.current_judgment == "needs_review":
        return _needs_review_remediation(request)
    if request.current_judgment == "likely_issue":
        return _likely_issue_remediation(request)
    if request.current_judgment == "likely_safe":
        return _likely_safe_remediation(request)
    return _needs_review_remediation(request)


def _overstates_likely_safe(remediation: str | None) -> bool:
    if remediation is None:
        return False
    normalized = remediation.lower()
    return (
        "vulnerab" in normalized or
        "exploit" in normalized or
        "sanitize input" in normalized
    )


def _overstates_uncertain_remediation(remediation: str | None) -> bool:
    if remediation is None:
        return False
    normalized = remediation.lower()
    return (
        "vulnerab" in normalized or
        "buffer overflow" in normalized or
        "exploit" in normalized or
        "compromis" in normalized
    )


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


def _likely_issue_reasoning(request: ReviewRequest) -> str:
    safe, ambiguous, positive, fallback = _split_guard_summary(request)
    parts = [
        "Deterministic judgment remains likely_issue because the compact context shows elevated risk at the sink, but the proof is still incomplete."
    ]
    if positive:
        parts.append(f"Risk signal: {positive}.")
    if ambiguous:
        parts.append(f"Unresolved point: {ambiguous}.")
    elif fallback:
        parts.append(f"Unresolved point: {fallback}.")
    elif safe:
        parts.append(f"Some safety evidence exists, but it does not yet close the proof gap: {safe}.")
    return " ".join(parts)


def _likely_safe_reasoning(request: ReviewRequest) -> str:
    safe, ambiguous, _, fallback = _split_guard_summary(request)
    parts = [
        "Deterministic judgment remains likely_safe because the compact context shows a safety signal near the sink, but the proof is still incomplete."
    ]
    if safe:
        parts.append(f"Current safety signal: {safe}.")
    if ambiguous:
        parts.append(f"Remaining gap: {ambiguous}.")
    elif not safe and fallback:
        parts.append(f"Remaining gap: {fallback}.")
    return " ".join(parts)


def _normalize_review_response(
    request: ReviewRequest,
    response: ReviewResponse,
    provider_status: str | None = None,
) -> ReviewResponse:
    remediation = response.remediation
    if request.current_judgment == "needs_review":
        if _is_generic_remediation(remediation) or _overstates_uncertain_remediation(remediation):
            remediation = _preferred_remediation(request)

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

    if request.current_judgment == "likely_issue":
        remediation = _preferred_remediation(request)

        normalized = response.model_copy(
            update={
                "judgment": "likely_issue",
                "confidence": min(response.confidence, request.confidence),
                "reasoning_summary": _truncate(_likely_issue_reasoning(request)),
                "remediation": _truncate(remediation) if remediation is not None else None,
                "safe_reasoning": None,
                "provider_status": provider_status or response.provider_status,
            }
        )
        validate_review_response(normalized)
        return normalized

    if request.current_judgment == "likely_safe":
        safe, _, _, _ = _split_guard_summary(request)
        remediation = _preferred_remediation(request)

        normalized = response.model_copy(
            update={
                "judgment": "likely_safe",
                "confidence": min(response.confidence, request.confidence),
                "reasoning_summary": _truncate(_likely_safe_reasoning(request)),
                "remediation": _truncate(remediation) if remediation is not None else None,
                "safe_reasoning": _truncate(safe) if safe else None,
                "provider_status": provider_status or response.provider_status,
            }
        )
        validate_review_response(normalized)
        return normalized

    updates: dict[str, object] = {}
    if provider_status is not None:
        updates["provider_status"] = provider_status
    normalized = response if not updates else response.model_copy(update=updates)
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
                remediation=_preferred_remediation(request),
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
