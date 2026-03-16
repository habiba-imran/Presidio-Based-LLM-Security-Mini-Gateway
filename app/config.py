import os
from dataclasses import dataclass


def _get_float_env(name: str, default: float) -> float:
    """
    Helper function to safely extract and parse environment variables as floats.
    If the variable is missing or cannot be parsed, the default value is returned.
    
    Args:
        name: The name of the environment variable (e.g., 'PII_THRESHOLD').
        default: The fallback float value.
        
    Returns:
        A parsed float representing the configuration value.
    """
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default


@dataclass(frozen=True)
class GatewayConfig:
    """
    Data structure holding all configuration parameters for the Security Gateway.
    Uses frozen=True to make the configuration immutable after initialization.
    """
    # Threshold above which a request is completely blocked (e.g., explicit jailbreaks)
    injection_block_threshold: float = 0.8
    # Threshold above which a request is allowed but with entities masked (e.g., mild policy violations)
    injection_mask_threshold: float = 0.4
    # Minimum confidence score for Presidio to consider an entity valid
    pii_threshold: float = 0.5
    
    # Feature flags
    use_llm: bool = False             # Whether the gateway should proceed to call an LLM after validation
    ollama_enabled: bool = False      # Whether a local Ollama instance is available
    
    # Ollama explicit configuration
    ollama_model: str = "llama3"
    ollama_fallback_model: str = "mistral"
    ollama_url: str = "http://localhost:11434/api/generate"

    @classmethod
    def from_env(cls) -> "GatewayConfig":
        """
        Factory method to instantiate GatewayConfig using system environment variables.
        Provides robust fallbacks for all parameters if not explicitly set in the environment.
        """
        # Parse boolean feature flags, accepting typical truthy string values
        use_llm = os.getenv("USE_LLM", "false").strip().lower() in {
            "1", "true", "yes", "on",
        }
        ollama_enabled = os.getenv("OLLAMA_ENABLED", "false").strip().lower() in {
            "1", "true", "yes", "on",
        }
        
        # Build and return the immutable configuration object
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