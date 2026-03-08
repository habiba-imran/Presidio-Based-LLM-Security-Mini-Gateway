def policy_decision(injection_score, pii_results):
    """
    Decide whether to ALLOW, MASK, or BLOCK the request
    """

    # High risk prompt injection
    if injection_score > 0.8:
        return "BLOCK"

    # Medium risk injection
    if injection_score > 0.4:
        return "MASK"

    # PII detected
    if len(pii_results) > 0:
        return "MASK"

    return "ALLOW"