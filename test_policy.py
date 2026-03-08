from app.policy_engine import policy_decision


class MockResult:
	def __init__(self, entity_type):
		self.entity_type = entity_type


def test_policy_block_by_injection_score():
	assert policy_decision(0.9, []) == "BLOCK"


def test_policy_mask_by_medium_injection_score():
	assert policy_decision(0.5, []) == "MASK"


def test_policy_mask_by_pii():
	assert policy_decision(0.1, [MockResult("PHONE_NUMBER")]) == "MASK"


def test_policy_allow_when_safe():
	assert policy_decision(0.1, []) == "ALLOW"


def test_policy_block_on_sensitive_entity():
	assert policy_decision(0.1, [MockResult("API_KEY")]) == "BLOCK"


def test_policy_uses_custom_thresholds():
	assert policy_decision(0.61, [], block_threshold=0.9, mask_threshold=0.6) == "MASK"