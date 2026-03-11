from __future__ import annotations

from jsonschema import Draft202012Validator

from .schemas import REQUEST_JSON_SCHEMA, RESPONSE_JSON_SCHEMA, ReviewRequest, ReviewResponse


REQUEST_VALIDATOR = Draft202012Validator(REQUEST_JSON_SCHEMA)
RESPONSE_VALIDATOR = Draft202012Validator(RESPONSE_JSON_SCHEMA)


def validate_review_request(request: ReviewRequest) -> None:
    REQUEST_VALIDATOR.validate(request.model_dump(mode="json"))


def validate_review_response(response: ReviewResponse) -> None:
    RESPONSE_VALIDATOR.validate(response.model_dump(mode="json"))
