from presidio_analyzer import PatternRecognizer, Pattern


def create_api_key_recognizer():
    """
    Custom recognizer for API keys
    """

    api_pattern = Pattern(
        name="api_key_pattern",
        regex=r"sk-[A-Za-z0-9]{32}",
        score=0.85
    )

    api_recognizer = PatternRecognizer(
        supported_entity="API_KEY",
        patterns=[api_pattern]
    )

    return api_recognizer


def create_employee_id_recognizer():
    """
    Context-aware recognizer for internal employee IDs
    """

    employee_pattern = Pattern(
        name="employee_id_pattern",
        regex=r"\b\d{5}\b",
        score=0.4
    )

    employee_recognizer = PatternRecognizer(
        supported_entity="EMPLOYEE_ID",
        patterns=[employee_pattern],
        context=["employee", "emp id", "employee id", "staff id"]
    )

    return employee_recognizer