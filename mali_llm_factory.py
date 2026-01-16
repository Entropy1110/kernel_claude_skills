"""
LLM Factory for Mali Static AI Skills

Provides configurable LLM instantiation based on mali-config.json settings.
Supports multiple modes: claude_code, hybrid, local_only, openrouter_only.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Literal

from langchain_ollama import ChatOllama
from langchain_openai import ChatOpenAI


DEFAULT_CONFIG_PATH = ".claude/config/mali-config.json"

# Provider type
ProviderType = Literal["claude_code", "ollama", "openrouter"]


class LLMFactory:
    """Factory for creating LLM instances based on configuration."""

    def __init__(self, config_path: str | Path | None = None):
        """
        Initialize LLM factory.

        Args:
            config_path: Path to mali-config.json. If None, uses default.
        """
        if config_path is None:
            candidates = [
                Path(__file__).parent / DEFAULT_CONFIG_PATH,
                Path.cwd() / DEFAULT_CONFIG_PATH,
            ]
            for candidate in candidates:
                if candidate.exists():
                    config_path = candidate
                    break
            else:
                raise FileNotFoundError(
                    f"Could not find mali-config.json. Searched: {[str(c) for c in candidates]}"
                )

        self.config_path = Path(config_path)
        self._config: dict[str, Any] | None = None
        self._llm_cache: dict[str, Any] = {}

    @property
    def config(self) -> dict[str, Any]:
        """Lazy-load configuration."""
        if self._config is None:
            with open(self.config_path, encoding="utf-8") as f:
                self._config = json.load(f)
        return self._config

    @property
    def mode(self) -> str:
        """Get current mode."""
        return self.config.get("mode", "claude_code")

    @property
    def is_claude_code_mode(self) -> bool:
        """Check if running in Claude Code mode."""
        return self.mode == "claude_code"

    def reload_config(self) -> None:
        """Force reload configuration."""
        self._config = None
        self._llm_cache.clear()

    def get_provider_for_stage(self, stage: str) -> ProviderType:
        """
        Get provider type for a pipeline stage.

        Args:
            stage: Pipeline stage name

        Returns:
            Provider type: "claude_code", "ollama", or "openrouter"
        """
        mode_config = self.config.get("modes", {}).get(self.mode, {})
        stage_providers = mode_config.get("stage_provider", {})
        return stage_providers.get(stage, "claude_code")

    def get_llm_for_stage(
        self,
        stage: str,
        override_provider: str | None = None,
        override_model: str | None = None,
    ) -> Any | None:
        """
        Get LLM instance for a pipeline stage.

        Args:
            stage: Pipeline stage name
            override_provider: Override provider type
            override_model: Override model name

        Returns:
            LangChain chat model or None if claude_code mode
        """
        provider = override_provider or self.get_provider_for_stage(stage)

        if provider == "claude_code":
            return None  # Claude Code handles directly

        return self._create_llm(provider, override_model)

    def _create_llm(
        self,
        provider: str,
        override_model: str | None = None,
    ) -> Any:
        """
        Create LLM instance.

        Args:
            provider: Provider name ("ollama" or "openrouter")
            override_model: Optional model override

        Returns:
            LangChain chat model
        """
        cache_key = f"{provider}:{override_model or 'default'}"
        if cache_key in self._llm_cache:
            return self._llm_cache[cache_key]

        providers = self.config.get("providers", {})
        if provider not in providers:
            raise ValueError(f"Unknown provider: {provider}")

        config = providers[provider]

        if provider == "ollama":
            model = override_model or config.get("model", "qwen2.5-coder:32b")
            llm = ChatOllama(
                model=model,
                base_url=config.get("base_url", "http://localhost:11434"),
                temperature=config.get("temperature", 0),
                timeout=config.get("timeout", 300),
            )
        elif provider == "openrouter":
            api_key_env = config.get("api_key_env", "OPENROUTER_API_KEY")
            api_key = os.getenv(api_key_env)
            if not api_key:
                raise ValueError(f"API key not found: {api_key_env}")

            model = override_model or config.get("model", "anthropic/claude-sonnet-4")
            llm = ChatOpenAI(
                model=model,
                openai_api_key=api_key,
                openai_api_base=config.get("base_url", "https://openrouter.ai/api/v1"),
                temperature=config.get("temperature", 0),
                timeout=config.get("timeout", 600),
                default_headers={
                    "HTTP-Referer": "https://github.com/mali-static-ai",
                    "X-Title": "mali-static-ai",
                },
            )
        else:
            raise ValueError(f"Unsupported provider: {provider}")

        self._llm_cache[cache_key] = llm
        return llm

    def get_model_for_stage(self, stage: str) -> str:
        """Get model name for a stage."""
        provider = self.get_provider_for_stage(stage)
        if provider == "claude_code":
            return "claude_code"
        providers = self.config.get("providers", {})
        return providers.get(provider, {}).get("model", "unknown")

    def estimate_cost(
        self,
        stage: str,
        input_tokens: int,
        output_tokens: int,
    ) -> float:
        """Estimate cost for a stage."""
        provider = self.get_provider_for_stage(stage)
        if provider == "claude_code":
            return 0.0  # No cost for Claude Code mode

        providers = self.config.get("providers", {})
        config = providers.get(provider, {})

        input_cost = (input_tokens / 1000) * config.get("cost_per_1k_input", 0)
        output_cost = (output_tokens / 1000) * config.get("cost_per_1k_output", 0)

        return input_cost + output_cost

    def get_all_stages(self) -> list[str]:
        """Get all configured stages."""
        mode_config = self.config.get("modes", {}).get(self.mode, {})
        return list(mode_config.get("stage_provider", {}).keys())

    def get_mode_info(self) -> dict[str, Any]:
        """Get information about current mode."""
        mode_config = self.config.get("modes", {}).get(self.mode, {})
        return {
            "mode": self.mode,
            "description": mode_config.get("description", ""),
            "stage_providers": mode_config.get("stage_provider", {}),
        }

    def list_available_modes(self) -> list[dict[str, str]]:
        """List all available modes."""
        modes = self.config.get("modes", {})
        return [
            {"name": name, "description": info.get("description", "")}
            for name, info in modes.items()
        ]


# Global instance
_default_factory: LLMFactory | None = None


def get_factory(config_path: str | Path | None = None) -> LLMFactory:
    """Get or create default LLM factory."""
    global _default_factory
    if _default_factory is None or config_path is not None:
        _default_factory = LLMFactory(config_path)
    return _default_factory


def get_llm_for_stage(
    stage: str,
    override_model: str | None = None,
    config_path: str | Path | None = None,
) -> Any | None:
    """Convenience function to get LLM for a stage."""
    factory = get_factory(config_path)
    return factory.get_llm_for_stage(stage, override_model=override_model)


def is_claude_code_mode(config_path: str | Path | None = None) -> bool:
    """Check if running in Claude Code mode."""
    factory = get_factory(config_path)
    return factory.is_claude_code_mode


if __name__ == "__main__":
    import sys

    try:
        factory = LLMFactory()
        print("LLM Factory initialized")
        print(f"Config: {factory.config_path}")
        print(f"\nCurrent mode: {factory.mode}")
        print(f"Is Claude Code mode: {factory.is_claude_code_mode}")

        print("\nMode info:")
        info = factory.get_mode_info()
        print(f"  Description: {info['description']}")
        print(f"  Stage providers:")
        for stage, provider in info["stage_providers"].items():
            print(f"    {stage}: {provider}")

        print("\nAvailable modes:")
        for mode in factory.list_available_modes():
            print(f"  - {mode['name']}: {mode['description']}")

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
