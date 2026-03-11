from __future__ import annotations

from jsonschema import ValidationError as JsonSchemaValidationError
from pydantic import ValidationError as PydanticValidationError
from tenacity import AsyncRetrying, retry_if_exception_type, stop_after_attempt, wait_exponential

from .providers import BaseProvider, ProviderError
from .schemas import ReviewRequest, ReviewResponse
from .settings import GatewaySettings
from .validation import validate_review_request, validate_review_response


class ReviewService:
    def __init__(self, provider: BaseProvider, settings: GatewaySettings) -> None:
        self._provider = provider
        self._settings = settings

    @staticmethod
    def should_route_to_llm(request: ReviewRequest) -> bool:
        return request.current_judgment in {"needs_review", "likely_issue", "likely_safe"}

    @staticmethod
    def fallback_response(request: ReviewRequest, reason: str) -> ReviewResponse:
        return ReviewResponse(
            judgment=request.current_judgment,
            confidence=request.confidence,
            cwe=None,
            exploitability="unknown",
            reasoning_summary=f"LLM review unavailable. {reason}",
            remediation=None,
            safe_reasoning=(
                "deterministic engine retained control because LLM review was skipped or failed"
                if request.current_judgment in {"likely_safe", "safe_suppressed"}
                else None
            ),
            provider_status="fallback",
        )

    async def review(self, request: ReviewRequest) -> ReviewResponse:
        validate_review_request(request)

        if not self._settings.enabled:
            response = self.fallback_response(request, "review is disabled by configuration")
            validate_review_response(response)
            return response

        if not self.should_route_to_llm(request):
            response = self.fallback_response(request, "LLM review skipped by routing policy")
            validate_review_response(response)
            return response

        try:
            async for attempt in AsyncRetrying(
                stop=stop_after_attempt(max(1, self._settings.max_retries)),
                wait=wait_exponential(multiplier=0.2, min=0.2, max=1.5),
                retry=retry_if_exception_type(ProviderError),
                reraise=True,
            ):
                with attempt:
                    try:
                        response = await self._provider.review(request)
                        validate_review_response(response)
                        return response
                    except (JsonSchemaValidationError, PydanticValidationError) as exc:
                        raise ProviderError(f"provider response failed schema validation: {exc}") from exc
        except ProviderError as exc:
            response = self.fallback_response(request, f"LLM provider failed: {exc}")
            validate_review_response(response)
            return response
