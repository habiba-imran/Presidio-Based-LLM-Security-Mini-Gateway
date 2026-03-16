import time
from typing import Dict

import requests


class LLMBackendError(Exception):
    """Custom exception raised when communication with the LLM backend fails."""
    pass


def _query_ollama(prompt: str, model: str, url: str, timeout: float = 20.0) -> Dict[str, object]:
    """
    Internal helper to send a single synchronous generation request to an Ollama server.
    Measures the latency of the individual network call.
    
    Args:
        prompt (str): The sanitized/masked user input to send to the LLM.
        model (str): The specific model name to request (e.g., 'llama3').
        url (str): The Ollama API endpoint URL.
        timeout (float): Connection and reading timeout in seconds.
        
    Returns:
        Dict[str, object]: A dictionary containing the generated 'text' and the 'latency'.
        
    Raises:
        LLMBackendError: If the HTTP request fails or times out.
    """
    start = time.time()

    # The payload structure expected by the Ollama REST API
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,  # Request the full response at once instead of SSE streaming
    }

    try:
        response = requests.post(url, json=payload, timeout=timeout)
        response.raise_for_status() # Raise HTTP errors (e.g., 404 Model Not Found)
        data = response.json()
    except Exception as exc:  # pragma: no cover
        raise LLMBackendError(str(exc)) from exc

    # Calculate inference latency
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
    """
    High-level wrapper to call Ollama with a built-in fallback strategy.
    If the primary model fails (e.g., not pulled locally or crashes), it automatically 
    attempts the secondary fallback model.
    
    Args:
        prompt (str): Text to send to the LLM.
        model (str): Primary model to attempt first.
        fallback_model (str): Secondary model to try if the primary fails.
        url (str): Server endpoint.
        timeout (float): Request timeout.
        
    Returns:
        Dict[str, object]: The generated response, including the name of the model finally used.
        
    Raises:
        LLMBackendError: If BOTH the primary and fallback models fail.
    """
    last_error = None
    
    # Iterate through our list of supported models in preferred order
    for candidate_model in [model, fallback_model]:
        try:
            result = _query_ollama(prompt=prompt, model=candidate_model, url=url, timeout=timeout)
            result["model_used"] = candidate_model
            return result
        except Exception as exc:  # pragma: no cover
            # Record the error and continue to the next model in the list
            last_error = exc

    # If the loop exhausts all candidate models without returning, the backend is strictly unavailable
    raise LLMBackendError(f"Both primary and fallback models failed. Last error: {last_error}") from last_error
