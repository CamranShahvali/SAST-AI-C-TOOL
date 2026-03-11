from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


Judgment = Literal[
    "confirmed_issue",
    "likely_issue",
    "needs_review",
    "likely_safe",
    "safe_suppressed",
]
Severity = Literal["low", "medium", "high", "critical"]
Exploitability = Literal["high", "medium", "low", "unknown"]
ProviderStatus = Literal["ok", "mock", "fallback", "error"]


class CodeWindow(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    file_path: str = Field(min_length=1, max_length=260)
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    snippet: str = Field(min_length=1, max_length=1200)

    @model_validator(mode="after")
    def validate_small_window(self) -> "CodeWindow":
        if self.end_line < self.start_line:
            raise ValueError("end_line must be greater than or equal to start_line")
        if self.end_line - self.start_line + 1 > 12:
            raise ValueError("code windows must be 12 lines or fewer")
        if self.snippet.count("\n") + 1 > 12:
            raise ValueError("snippet must be 12 lines or fewer")
        return self


class ReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    candidate_id: str = Field(min_length=1, max_length=128)
    rule_id: str = Field(min_length=1, max_length=128)
    current_judgment: Judgment
    provisional_severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    source_summary: str = Field(min_length=1, max_length=600)
    sink_summary: str = Field(min_length=1, max_length=600)
    path_summary: str = Field(min_length=1, max_length=1000)
    guard_summary: str = Field(min_length=1, max_length=1000)
    code_windows: list[CodeWindow] = Field(min_length=1, max_length=2)

    @model_validator(mode="after")
    def validate_compact_context(self) -> "ReviewRequest":
        total_chars = sum(len(window.snippet) for window in self.code_windows)
        if total_chars > 1600:
            raise ValueError("code window payload is too large")
        return self


class ReviewResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    judgment: Judgment
    confidence: float = Field(ge=0.0, le=1.0)
    cwe: str | None = Field(default=None, max_length=64)
    exploitability: Exploitability
    reasoning_summary: str = Field(min_length=1, max_length=1200)
    remediation: str | None = Field(default=None, max_length=1200)
    safe_reasoning: str | None = Field(default=None, max_length=1200)
    provider_status: ProviderStatus = "ok"


REQUEST_JSON_SCHEMA = ReviewRequest.model_json_schema()
RESPONSE_JSON_SCHEMA = ReviewResponse.model_json_schema()
