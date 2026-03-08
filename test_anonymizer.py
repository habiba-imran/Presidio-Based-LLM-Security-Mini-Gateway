from app.presidio_module.analyzer import analyze_pii
from app.presidio_module.anonymizer import anonymize_text


def test_anonymize_text_masks_detected_entities():
	text = "My phone number is 03001234567 and email is test@gmail.com"
	pii_results = analyze_pii(text)
	masked_text = anonymize_text(text, pii_results)

	assert masked_text != text
	assert "test@gmail.com" not in masked_text