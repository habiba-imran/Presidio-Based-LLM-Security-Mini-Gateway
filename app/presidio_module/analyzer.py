from presidio_analyzer import AnalyzerEngine
from app.presidio_module.custom_recognizers import (
    create_api_key_recognizer,
    create_employee_id_recognizer
)

analyzer = AnalyzerEngine()

# register custom recognizers
api_recognizer = create_api_key_recognizer()
employee_recognizer = create_employee_id_recognizer()

analyzer.registry.add_recognizer(api_recognizer)
analyzer.registry.add_recognizer(employee_recognizer)


def analyze_pii(text: str, threshold=0.5):
    """
    Detect PII entities and filter by confidence threshold
    """

    results = analyzer.analyze(
        text=text,
        language="en"
    )

    # filter low confidence detections
    filtered_results = [r for r in results if r.score >= threshold]

    return filtered_results