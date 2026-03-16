def policy_decision(
    injection_score,
    pii_results,
    block_threshold=0.8,
    mask_threshold=0.4,
):
    """
    Decide the final security action (ALLOW, MASK, or BLOCK) for a given request.
    
    The engine evaluates both explicit adversarial threats (injection) and 
    passive data-leak threats (PII extraction).
    
    Args:
        injection_score (float): The calculated threat score (0.0 to 1.0).
        pii_results (List[RecognizerResult]): List of entities detected by Presidio.
        block_threshold (float): Minimum score required to outright block a payload.
        mask_threshold (float): Minimum score required to apply PII masking.
        
    Returns:
        str: "BLOCK" (hard stop), "MASK" (proceed with anonymized text), or "ALLOW" (safe).
    """

    # 1. Immediate termination if a severe prompt injection/jailbreak is detected.
    if injection_score > block_threshold:
        return "BLOCK"

    # 2. Medium-threat injection attempts (e.g. slight constraint overrides)
    # trigger a 'MASK' response to operate defensively.
    if injection_score > mask_threshold:
        return "MASK"

    # 3. Assess data exfiltration risk based on specific highly-sensitive PII types.
    # E.g., leaking an internal API Key or a composite Employee Contact is a critical violation.
    high_sensitivity_entities = {"API_KEY", "COMPOSITE_CONTACT"}
    for item in pii_results:
        # Compatibility fallback: get entity type depending on how the Presidio result is structured
        entity_type = getattr(item, "entity_type", str(item))
        if entity_type in high_sensitivity_entities:
            return "BLOCK"

    # 4. If any standard PII is found (e.g., standard phone number, generic employee ID), 
    # we don't block the request, but we enforce masking to protect privacy.
    if len(pii_results) > 0:
        return "MASK"

    # 5. The payload is benign, contains no risky instructions, and has no PII.
    return "ALLOW"