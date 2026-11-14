from __future__ import annotations

import pytest

from beacon.config import NightShiftConfig


def test_parses_selectors_and_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOG_SELECTORS", '{namespace="demo"} ; {app="api"}')
    for name in ("LLM_MODEL_ID", "LOOKBACK_MINUTES", "INCIDENTS_ENABLED"):
        monkeypatch.delenv(name, raising=False)
    config = NightShiftConfig.from_env()
    assert config.log_group_patterns == ['{namespace="demo"}', '{app="api"}']
    assert config.lookback_minutes == 30 and config.incidents_enabled
    assert config.incidents_table_name == "incidents"


def test_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOOKBACK_MINUTES", "60")
    monkeypatch.setenv("APPLY_ENABLED", "false")
    config = NightShiftConfig.from_env()
    assert config.lookback_minutes == 60 and config.apply_enabled is False


def test_selectors_are_required(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LOG_SELECTORS")
    with pytest.raises(ValueError, match="LOG_SELECTORS"):
        NightShiftConfig.from_env()


def test_models_run_on_ollama_not_a_cloud_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("LLM_MODEL_ID", raising=False)
    monkeypatch.delenv("EMBEDDING_MODEL_ID", raising=False)
    config = NightShiftConfig.from_env()
    assert config.litellm_model.startswith("ollama_chat/")
    assert config.embedding_model_id.startswith("ollama/")
    assert "bedrock" not in config.litellm_model


def test_bare_model_name_is_routed_to_ollama(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LLM_MODEL_ID", "llama3.1")
    assert NightShiftConfig.from_env().litellm_model == "ollama_chat/llama3.1"
