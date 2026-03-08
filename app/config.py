import os
from dataclasses import dataclass


def _get_float_env(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default


@dataclass(frozen=True)
class GatewayConfig:
    injection_block_threshold: float = 0.8
    injection_mask_threshold: float = 0.4
    pii_threshold: float = 0.5
    use_llm: bool = False
    ollama_enabled: bool = False
    ollama_model: str = "llama3"
    ollama_fallback_model: str = "mistral"
    ollama_url: str = "http://localhost:11434/api/generate"

    @classmethod
    def from_env(cls) -> "GatewayConfig":
        use_llm = os.getenv("USE_LLM", "false").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        ollama_enabled = os.getenv("OLLAMA_ENABLED", "false").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        return cls(
            injection_block_threshold=_get_float_env("INJECTION_BLOCK_THRESHOLD", 0.8),
            injection_mask_threshold=_get_float_env("INJECTION_MASK_THRESHOLD", 0.4),
            pii_threshold=_get_float_env("PII_THRESHOLD", 0.5),
            use_llm=use_llm,
            ollama_enabled=ollama_enabled,
            ollama_model=os.getenv("OLLAMA_MODEL", "llama3"),
            ollama_fallback_model=os.getenv("OLLAMA_FALLBACK_MODEL", "mistral"),
            ollama_url=os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate"),
        )