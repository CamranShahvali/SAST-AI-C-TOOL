from __future__ import annotations

from dataclasses import dataclass
import os


def _parse_bool(name: str, default: str) -> bool:
    value = os.getenv(name, default).strip().lower()
    return value not in {"0", "false", "no", "off"}


@dataclass(frozen=True)
class GatewaySettings:
    enabled: bool = _parse_bool("SAST_LLM_ENABLED", "1")
    provider: str = os.getenv("SAST_LLM_PROVIDER", "mock")
    base_url: str = os.getenv("SAST_LLM_BASE_URL", "https://api.openai.com")
    api_key: str = os.getenv("OPENAI_API_KEY", "")
    model: str = os.getenv("SAST_LLM_MODEL", "mock-reviewer-v1")
    timeout_seconds: float = float(os.getenv("SAST_LLM_TIMEOUT", "20"))
    max_retries: int = int(os.getenv("SAST_LLM_MAX_RETRIES", "2"))


def load_settings() -> GatewaySettings:
    return GatewaySettings()
