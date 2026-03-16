from app.config import GatewayConfig
from app.injection_detector import detect_injection
from app.llm_backend import LLMBackendError, call_llm_with_ollama
from app.presidio_module.analyzer import analyze_pii
from app.presidio_module.anonymizer import anonymize_text
from app.policy_engine import policy_decision
from app.utils.latency import measure_latency


def gateway_process(user_input, config: GatewayConfig | None = None):
    """
    Core security pipeline that processes user input before it reaches an LLM.
    Execution order: Injection Detection -> PII Detection -> Policy Decision -> Anonymization (if needed).
    
    Args:
        user_input (str): The raw text submitted by the user.
        config (GatewayConfig, optional): Configuration settings. Defaults to environment config.
        
    Returns:
        dict: Contains the final 'decision' (ALLOW/MASK/BLOCK), the processed 'output' string, 
              and the 'latency' taken to compute the result.
    """
    # Initialize default configuration if none is provided
    if config is None:
        config = GatewayConfig.from_env()

    # Utilize a context manager to track total operation latency cleanly
    with measure_latency() as metrics:
        
        # 1. Detect prompt injections and malicious instructions
        injection_score = detect_injection(user_input)

        # 2. Analyze text for sensitive PII entities using Microsoft Presidio
        pii_results = analyze_pii(user_input, threshold=config.pii_threshold)

        # 3. Determine action based on aggregated threat and sensitivity scores
        decision = policy_decision(
            injection_score,
            pii_results,
            block_threshold=config.injection_block_threshold,
            mask_threshold=config.injection_mask_threshold,
        )

        # 4. Apply the policy outcome to generate the final safe output
        if decision == "BLOCK":
            # Hard stop: do not pass any context forward
            output = "Request blocked due to security policy."

        elif decision == "MASK":
            # Mitigation: replace sensitive entities with generic tags (e.g., <PERSON>)
            output = anonymize_text(user_input, pii_results)

        else:
            # Safe: return original input
            output = user_input

    # Return the structured result containing the pipeline outcome
    return {
        "decision": decision,
        "output": output,
        "latency": metrics["latency"]
    }


def gateway_process_with_llm(user_input, config: GatewayConfig | None = None):
    """
    Extended gateway pipeline that includes invoking a local LLM if the security policy allows it.
    This serves as the bonus component integrating the security gateway with an actual backend.
    
    Args:
        user_input (str): The raw text submitted by the user.
        config (GatewayConfig, optional): Configuration settings mapping Ollama URLs/models.
        
    Returns:
        dict: The base gateway results appended with LLM inference outputs and extended latency metrics.
    """
    if config is None:
        config = GatewayConfig.from_env()

    # Step 1: Execute the core security evaluation
    base = gateway_process(user_input, config=config)

    # Step 2: Determine if the LLM backend should be queried
    llm_enabled = config.use_llm or config.ollama_enabled
    
    # If the request was blocked by security, or LLMs are disabled, short-circuit and return immediately
    if base["decision"] == "BLOCK" or not llm_enabled:
        base["llm_used"] = False
        base["llm_latency"] = 0.0
        base["total_with_llm_latency"] = base["latency"]
        base["llm_error"] = ""
        return base

    # Step 3: Attempt to call the LLM using the sanitized output from the gateway
    try:
        # Pass the safe 'base["output"]' (which may be masked) to Ollama, not the raw 'user_input'
        llm_result = call_llm_with_ollama(
            prompt=base["output"],
            model=config.ollama_model,
            fallback_model=config.ollama_fallback_model,
            url=config.ollama_url,
        )
        # Update result dictionary with successful LLM metrics
        base["llm_used"] = True
        base["llm_latency"] = llm_result["latency"]
        base["llm_output"] = llm_result["text"]
        base["llm_model_used"] = llm_result.get("model_used", "")
        # Calculate end-to-end latency (security checks + model text generation)
        base["total_with_llm_latency"] = base["latency"] + base["llm_latency"]
        base["llm_error"] = ""
        return base
        
    except LLMBackendError as exc:
        # Gracefully handle API failures (e.g., Ollama server is offline) without crashing the primary pipeline
        base["llm_used"] = True
        base["llm_latency"] = 0.0
        base["total_with_llm_latency"] = base["latency"]
        base["llm_error"] = str(exc) # Provide the error string for debugging
        return base