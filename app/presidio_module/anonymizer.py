from presidio_anonymizer import AnonymizerEngine

# Initialize the global anonymizer engine to avoid reboot overhead per request
anonymizer = AnonymizerEngine()


def anonymize_text(text, analyzer_results):
    """
    Masks the detected PII entities in the source text.
    Replaces sensitive spans with descriptive placeholders (e.g., <PERSON>, <API_KEY>).
    
    Args:
        text (str): Original text containing sensitive information.
        analyzer_results (List[RecognizerResult]): The entities detected by the Presidio analyzer.
        
    Returns:
        str: A safe, anonymized string ready to be passed to the LLM.
    """

    result = anonymizer.anonymize(
        text=text,
        analyzer_results=analyzer_results
    )

    return result.text