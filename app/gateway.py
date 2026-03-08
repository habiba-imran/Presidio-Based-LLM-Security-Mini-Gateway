import time

from app.injection_detector import detect_injection
from app.presidio_module.analyzer import analyze_pii
from app.presidio_module.anonymizer import anonymize_text
from app.policy_engine import policy_decision


def gateway_process(user_input):

    start_total = time.time()

    injection_score = detect_injection(user_input)

    pii_results = analyze_pii(user_input)

    decision = policy_decision(injection_score, pii_results)

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