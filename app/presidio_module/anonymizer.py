from presidio_anonymizer import AnonymizerEngine


# initialize anonymizer
anonymizer = AnonymizerEngine()


def anonymize_text(text, analyzer_results):
    """
    Masks detected PII entities
    """

    result = anonymizer.anonymize(
        text=text,
        analyzer_results=analyzer_results
    )

    return result.text