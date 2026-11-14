from __future__ import annotations

import os
from dataclasses import dataclass

_DEFAULT_MODEL_ID = "ollama_chat/qwen2.5:7b"
_DEFAULT_EMBEDDING_MODEL_ID = "ollama/nomic-embed-text"


@dataclass(frozen=True, slots=True)
class NightShiftConfig:
    """Immutable configuration for one triage run (from the environment)."""

    log_group_patterns: list[str]  # Loki stream selectors, e.g. {namespace="demo"}
    lookback_minutes: int = 30
    cordon_backend: str = "remote"
    cordon_window_size: int = 4
    cordon_k_neighbors: int = 5
    llm_model_id: str = _DEFAULT_MODEL_ID
    embedding_model_id: str = _DEFAULT_EMBEDDING_MODEL_ID
    token_budget: int = 0  # 0 = use model context window
    max_output_tokens: int = 2048
    call_enabled: bool = False
    oncall_phone: str = ""
    incidents_table_name: str = "incidents"
    incidents_enabled: bool = True
    dashboard_url: str = ""
    apply_enabled: bool = True

    @classmethod
    def from_env(cls) -> NightShiftConfig:
        """Build a NightShiftConfig from environment variables.

        Raises ``ValueError`` if ``LOG_SELECTORS`` is missing or empty.
        """
        raw = os.environ.get("LOG_SELECTORS", "")
        patterns = [p.strip() for p in raw.split(";") if p.strip()]
        if not patterns:
            raise ValueError("LOG_SELECTORS environment variable is required")
        return cls(
            log_group_patterns=patterns,
            lookback_minutes=int(os.environ.get("LOOKBACK_MINUTES", "30")),
            cordon_backend=os.environ.get("CORDON_BACKEND", "remote"),
            cordon_window_size=int(os.environ.get("CORDON_WINDOW_SIZE", "4")),
            cordon_k_neighbors=int(os.environ.get("CORDON_K_NEIGHBORS", "5")),
            llm_model_id=os.environ.get("LLM_MODEL_ID", _DEFAULT_MODEL_ID),
            embedding_model_id=os.environ.get(
                "EMBEDDING_MODEL_ID", _DEFAULT_EMBEDDING_MODEL_ID
            ),
            token_budget=int(os.environ.get("TOKEN_BUDGET", "0")),
            max_output_tokens=int(os.environ.get("MAX_OUTPUT_TOKENS", "2048")),
            call_enabled=os.environ.get("CALL_ENABLED", "").lower() == "true",
            oncall_phone=os.environ.get("ONCALL_PHONE", ""),
            incidents_table_name=os.environ.get("INCIDENTS_TABLE_NAME", "incidents"),
            incidents_enabled=os.environ.get("INCIDENTS_ENABLED", "true").lower()
            != "false",
            dashboard_url=os.environ.get("DASHBOARD_URL", ""),
            apply_enabled=os.environ.get("APPLY_ENABLED", "true").lower() != "false",
        )

    @property
    def litellm_model(self) -> str:
        """Model id for litellm; a bare name is routed to the local Ollama."""
        if "/" in self.llm_model_id:
            return self.llm_model_id
        return f"ollama_chat/{self.llm_model_id}"
