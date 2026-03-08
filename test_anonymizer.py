from app.presidio_module.analyzer import analyze_pii
from app.presidio_module.anonymizer import anonymize_text


text = "My phone number is 03001234567 and email is test@gmail.com"

pii_results = analyze_pii(text)

masked_text = anonymize_text(text, pii_results)

print("Original:", text)
print("Masked:", masked_text)