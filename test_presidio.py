from app.presidio_module.analyzer import analyze_pii


def test_analyze_employee_id_detection():
    text = "Employee ID: 87342"
    results = analyze_pii(text)
    entity_types = {r.entity_type for r in results}
    assert "EMPLOYEE_ID" in entity_types


def test_analyze_api_key_detection():
    text = "Leaked secret token sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    results = analyze_pii(text)
    entity_types = {r.entity_type for r in results}
    assert "API_KEY" in entity_types


def test_composite_contact_detection():
    text = "Contact me at test@gmail.com or 03001234567"
    results = analyze_pii(text)
    entity_types = {r.entity_type for r in results}
    assert "COMPOSITE_CONTACT" in entity_types