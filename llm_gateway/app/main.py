from __future__ import annotations

from fastapi import FastAPI

from .providers import create_provider
from .schemas import REQUEST_JSON_SCHEMA, RESPONSE_JSON_SCHEMA, ReviewRequest, ReviewResponse
from .service import ReviewService
from .settings import GatewaySettings, load_settings
from .validation import validate_review_request, validate_review_response


def build_app(
    service: ReviewService | None = None,
    settings: GatewaySettings | None = None,
) -> FastAPI:
    resolved_settings = settings or load_settings()
    resolved_service = service or ReviewService(create_provider(resolved_settings), resolved_settings)
    app = FastAPI(title="ai_sast llm_gateway", version="0.2.0")

    @app.get("/health")
    async def health() -> dict:
        return {
            "status": "ok",
            "enabled": resolved_settings.enabled,
            "provider": resolved_settings.provider,
            "model": resolved_settings.model,
        }

    @app.get("/schema/request")
    async def request_schema() -> dict:
        return REQUEST_JSON_SCHEMA

    @app.get("/schema/response")
    async def response_schema() -> dict:
        return RESPONSE_JSON_SCHEMA

    @app.post("/review", response_model=ReviewResponse)
    async def review(request: ReviewRequest) -> ReviewResponse:
        validate_review_request(request)
        response = await resolved_service.review(request)
        validate_review_response(response)
        return response

    return app


settings = load_settings()
service = ReviewService(create_provider(settings), settings)
app = build_app(service=service, settings=settings)
