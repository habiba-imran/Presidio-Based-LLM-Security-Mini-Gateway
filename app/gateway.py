import time

from app.config import GatewayConfig
from app.injection_detector import detect_injection
from app.llm_backend import LLMBackendError, call_llm_with_ollama
from app.presidio_module.analyzer import analyze_pii
from app.presidio_module.anonymizer import anonymize_text
from app.policy_engine import policy_decision


def gateway_process(user_input, config: GatewayConfig | None = None):

    if config is None:
        config = GatewayConfig.from_env()

    start_total = time.time()

    injection_score = detect_injection(user_input)

    pii_results = analyze_pii(user_input, threshold=config.pii_threshold)

    decision = policy_decision(
        injection_score,
        pii_results,
        block_threshold=config.injection_block_threshold,
        mask_threshold=config.injection_mask_threshold,
    )

    if decision == "BLOCK":
        output = "Request blocked due to security policy."

    elif decision == "MASK":
        output = anonymize_text(user_input, pii_results)

    else:
        output = user_input

    end_total = time.time()

    total_latency = end_total - start_total

    return {
        "decision": decision,
        "output": output,
        "latency": total_latency
    }


def gateway_process_with_llm(user_input, config: GatewayConfig | None = None):
    if config is None:
        config = GatewayConfig.from_env()

    base = gateway_process(user_input, config=config)

    # Policy controls LLM invocation: BLOCK never calls LLM.
    llm_enabled = config.use_llm or config.ollama_enabled
    if base["decision"] == "BLOCK" or not llm_enabled:
        base["llm_used"] = False
        base["llm_latency"] = 0.0
        base["total_with_llm_latency"] = base["latency"]
        base["llm_error"] = ""
        return base

    try:
        # LLM is called only for ALLOW or MASK; MASK sends masked output from gateway_process.
        llm_result = call_llm_with_ollama(
            prompt=base["output"],
            model=config.ollama_model,
            fallback_model=config.ollama_fallback_model,
            url=config.ollama_url,
        )
        # Latency breakdown keeps base gateway latency and adds LLM inference time.
        base["llm_used"] = True
        base["llm_latency"] = llm_result["latency"]
        base["llm_output"] = llm_result["text"]
        base["llm_model_used"] = llm_result.get("model_used", "")
        base["total_with_llm_latency"] = base["latency"] + base["llm_latency"]
        base["llm_error"] = ""
        return base
    except LLMBackendError as exc:
        # API failure is captured without crashing the pipeline.
        base["llm_used"] = True
        base["llm_latency"] = 0.0
        base["total_with_llm_latency"] = base["latency"]
        base["llm_error"] = str(exc)
        return base