def policy_decision(
    injection_score,
    pii_results,
    block_threshold=0.8,
    mask_threshold=0.4,
):
    """Decide whether to ALLOW, MASK, or BLOCK the request."""

    if injection_score > block_threshold:
        return "BLOCK"

    if injection_score > mask_threshold:
        return "MASK"

    high_sensitivity_entities = {"API_KEY", "COMPOSITE_CONTACT"}
    for item in pii_results:
        entity_type = getattr(item, "entity_type", str(item))
        if entity_type in high_sensitivity_entities:
            return "BLOCK"

    if len(pii_results) > 0:
        return "MASK"

    return "ALLOW"