"""Application configuration, loaded from environment variables (prefix ``VT_``)."""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VT_", env_file=".env", extra="ignore")

    environment: str = "local"

    # LLM provider cascade for remediation notes. Each reads its own API key from
    # the environment; when all fail, a templated note is used instead.
    llm_spec: str = "anthropic,openai,gemini,deepseek,ollama"
    llm_max_tokens: int = 200


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
