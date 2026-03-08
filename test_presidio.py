from app.presidio_module.analyzer import analyze_pii

text = "Employee ID: 87342"

results = analyze_pii(text)

for r in results:
    print(r.entity_type, r.score)