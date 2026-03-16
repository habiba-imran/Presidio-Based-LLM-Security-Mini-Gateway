from presidio_analyzer import AnalyzerEngine, RecognizerResult
from app.presidio_module.custom_recognizers import (
    create_api_key_recognizer,
    create_employee_id_recognizer,
    create_internal_id_recognizer,
)

# Initialize the core Presidio Analyzer Engine using default English NLP models
analyzer = AnalyzerEngine()

# Register custom recognizers to expand Presidio's default capabilities (e.g., PERSON, PHONE_NUMBER)
api_recognizer = create_api_key_recognizer()
employee_recognizer = create_employee_id_recognizer()
internal_id_recognizer = create_internal_id_recognizer()

analyzer.registry.add_recognizer(api_recognizer)
analyzer.registry.add_recognizer(employee_recognizer)
analyzer.registry.add_recognizer(internal_id_recognizer)


# Contextual keywords that, if found near a candidate entity, increase the confidence that the entity is real
CONTEXT_HINTS = {
    "EMPLOYEE_ID": ["employee", "emp id", "employee id", "staff id"],
    "API_KEY": ["api key", "secret", "token", "credential"],
    "INTERNAL_ID": ["ticket", "internal", "incident", "case"],
}


# Multipliers applied to the raw Presidio confidence score to boost or penalize specific entity types
CALIBRATION_FACTORS = {
    "API_KEY": 1.10,        # Boost API keys slightly as they are highly sensitive and pattern-distinct
    "EMPLOYEE_ID": 1.15,    # Employees are hard to detect by regex alone; boost when matched
    "INTERNAL_ID": 1.05,    
    "PHONE_NUMBER": 1.00,   # Keep default scoring for standard entities
    "EMAIL_ADDRESS": 1.00,
}


def _context_bonus(text: str, result: RecognizerResult) -> float:
    """
    Looks for contextual hints within a 40-character sliding window around the detected entity.
    If a hint is found (e.g., the word 'secret' right before an API key), a flat bonus is awarded.
    
    Args:
        text: The full string being analyzed.
        result: The individual entity detected by Presidio.
        
    Returns:
        float: 0.15 if context is found, 0.0 otherwise.
    """
    hints = CONTEXT_HINTS.get(result.entity_type, [])
    if not hints:
        return 0.0

    # Define a 40-character window before and after the entity
    start = max(0, result.start - 40)
    end = min(len(text), result.end + 40)
    window = text[start:end].lower()

    if any(hint in window for hint in hints):
        return 0.15
    return 0.0


def _calibrate_score(result: RecognizerResult) -> None:
    """
    Applies flat structural multipliers to the confidence score based on entity type.
    Modifies the result object in-place.
    """
    factor = CALIBRATION_FACTORS.get(result.entity_type, 1.0)
    # Ensure the score never exceeds 1.0 after multiplication
    result.score = min(1.0, result.score * factor)


def _add_composite_entities(results):
    """
    Analyzes the list of detected entities to find logical groupings.
    Specifically checks if a phone number and email occur in the same payload,
    which represents a high-risk 'COMPOSITE_CONTACT' leak.
    
    Args:
        results: List of standard RecognizerResults.
        
    Returns:
        List: The original results plus any generated composite entities.
    """
    phone_results = [r for r in results if r.entity_type == "PHONE_NUMBER"]
    email_results = [r for r in results if r.entity_type == "EMAIL_ADDRESS"]

    # Only create composite if BOTH exist
    if not phone_results or not email_results:
        return results

    # The composite spans from the start of the first entity to the end of the last
    start = min(min(r.start for r in phone_results), min(r.start for r in email_results))
    end = max(max(r.end for r in phone_results), max(r.end for r in email_results))

    composite = RecognizerResult(
        entity_type="COMPOSITE_CONTACT",
        start=start,
        end=end,
        score=0.9, # High confidence because two distinct contact types were found
    )
    return results + [composite]


def analyze_pii(text: str, threshold=0.5):
    """
    Main entry point for PII detection. Runs Presidio's engine, applies custom contexts, 
    calibrates confidence, generates composites, and drops low-confidence noise.
    
    Args:
        text (str): Raw string to analyze.
        threshold (float): Minimum final confidence score to retain an entity.
        
    Returns:
        List[RecognizerResult]: Filtered list of confirmed entities.
    """
    # 1. Base Presidio analysis
    results = analyzer.analyze(
        text=text,
        language="en"
    )

    # 2. Apply custom confidence adjustments (Context + Calibrations)
    for result in results:
        # Add context bonus (capped at 1.0)
        result.score = min(1.0, result.score + _context_bonus(text, result))
        # Multiply by calibration factor (capped at 1.0)
        _calibrate_score(result)

    # 3. Detect higher-order threats (e.g., Phone + Email = Contact)
    results = _add_composite_entities(results)

    # 4. Filter out any detections that don't meet the threshold
    filtered_results = [r for r in results if r.score >= threshold]

    return filtered_results