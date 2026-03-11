from fastapi.testclient import TestClient

from llm_gateway.app.main import build_app
from llm_gateway.app.providers import MockProvider
from llm_gateway.app.service import ReviewService
from llm_gateway.app.settings import GatewaySettings


def sample_payload() -> dict:
    return {
        "candidate_id": "cand-1",
        "rule_id": "dangerous_string.unbounded_copy",
        "current_judgment": "needs_review",
        "provisional_severity": "high",
        "confidence": 0.58,
        "source_summary": "argv[1]",
        "sink_summary": "memcpy(destination, argv[1], length)",
        "path_summary": "argv[1] -> destination",
        "guard_summary": "copy bound expression could not be proven",
        "code_windows": [
            {
                "file_path": "demo.cpp",
                "start_line": 12,
                "end_line": 15,
                "snippet": "char destination[8];\nstd::memcpy(destination, argv[1], length);",
            }
        ],
    }


def test_schema_endpoints_expose_contracts() -> None:
    settings = GatewaySettings(provider="mock")
    app = build_app(
        service=ReviewService(MockProvider(settings), settings),
        settings=settings,
    )
    client = TestClient(app)

    request_schema = client.get("/schema/request")
    response_schema = client.get("/schema/response")

    assert request_schema.status_code == 200
    assert response_schema.status_code == 200
    assert request_schema.json()["title"] == "ReviewRequest"
    assert response_schema.json()["title"] == "ReviewResponse"


def test_review_endpoint_uses_mock_provider() -> None:
    settings = GatewaySettings(provider="mock")
    app = build_app(
        service=ReviewService(MockProvider(settings), settings),
        settings=settings,
    )
    client = TestClient(app)

    response = client.post("/review", json=sample_payload())

    assert response.status_code == 200
    body = response.json()
    assert body["provider_status"] == "mock"
    assert body["judgment"] == "needs_review"
    assert "reasoning_summary" in body


def test_review_endpoint_rejects_large_window_payload() -> None:
    settings = GatewaySettings(provider="mock")
    app = build_app(
        service=ReviewService(MockProvider(settings), settings),
        settings=settings,
    )
    client = TestClient(app)

    payload = sample_payload()
    payload["code_windows"][0]["end_line"] = 30

    response = client.post("/review", json=payload)

    assert response.status_code == 422
