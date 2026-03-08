import time
from typing import Dict

import requests


class LLMBackendError(Exception):
    pass


def _query_ollama(prompt: str, model: str, url: str, timeout: float = 20.0) -> Dict[str, object]:
    start = time.time()

    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
    }

    try:
        response = requests.post(url, json=payload, timeout=timeout)
        response.raise_for_status()
        data = response.json()
    except Exception as exc:  # pragma: no cover
        raise LLMBackendError(str(exc)) from exc

    latency = time.time() - start
    return {
        "text": data.get("response", ""),
        "latency": latency,
    }


def call_llm_with_ollama(
    prompt: str,
    model: str = "llama3",
    fallback_model: str = "mistral",
    url: str = "http://localhost:11434/api/generate",
    timeout: float = 20.0,
) -> Dict[str, object]:
    """Call Ollama with primary model and fallback to mistral when needed."""

    last_error = None
    for candidate_model in [model, fallback_model]:
        try:
            result = _query_ollama(prompt=prompt, model=candidate_model, url=url, timeout=timeout)
            result["model_used"] = candidate_model
            return result
        except Exception as exc:  # pragma: no cover
            last_error = exc

    raise LLMBackendError(str(last_error)) from last_error
