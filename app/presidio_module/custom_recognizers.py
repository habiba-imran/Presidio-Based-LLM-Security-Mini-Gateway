from presidio_analyzer import PatternRecognizer, Pattern


def create_api_key_recognizer():
    """
    Builds a custom recognizer to detect leaked API keys.
    Specifically targets standard 'sk-...' formatted secret keys (e.g., OpenAI tokens).
    
    Returns:
        PatternRecognizer: A configured Presidio recognizer for 'API_KEY'.
    """

    api_pattern = Pattern(
        name="api_key_pattern",
        regex=r"sk-[A-Za-z0-9]{32}", # Matches 'sk-' followed by 32 alphanumeric chars
        score=0.85 # High base confidence due to specific regex structure
    )

    api_recognizer = PatternRecognizer(
        supported_entity="API_KEY",
        patterns=[api_pattern]
    )

    return api_recognizer


def create_employee_id_recognizer():
    """
    Builds a context-aware recognizer for internal 5-digit employee IDs.
    Because 5 digits can be anything (zip codes, random numbers), this uses 
    contextual hints to boost confidence only when relevant words are nearby.
    
    Returns:
        PatternRecognizer: A configured Presidio recognizer for 'EMPLOYEE_ID'.
    """

    employee_pattern = Pattern(
        name="employee_id_pattern",
        regex=r"\b\d{5}\b", # Matches exactly 5 consecutive digits
        score=0.4 # Low base confidence, relies on context bonus to cross the 0.5 threshold
    )

    employee_recognizer = PatternRecognizer(
        supported_entity="EMPLOYEE_ID",
        patterns=[employee_pattern],
        # If these words are found near the 5 digits, Presidio increases the confidence score
        context=["employee", "emp id", "employee id", "staff id"]
    )

    return employee_recognizer


def create_internal_id_recognizer():
    """
    Builds a custom recognizer for proprietary internal ticket/case IDs.
    Designed to prevent leakage of internal tracking numbers (e.g., INT-ABC-1234).
    
    Returns:
        PatternRecognizer: A configured Presidio recognizer for 'INTERNAL_ID'.
    """

    internal_pattern = Pattern(
        name="internal_id_pattern",
        regex=r"\bINT-[A-Z]{3}-\d{4}\b", # e.g., INT-XYZ-9999
        score=0.6 # Medium-high base confidence due to rigid formatting
    )

    internal_recognizer = PatternRecognizer(
        supported_entity="INTERNAL_ID",
        patterns=[internal_pattern],
        # Context hints help push confidence even higher
        context=["ticket", "internal", "incident", "case"]
    )

    return internal_recognizer