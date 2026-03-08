import re

INJECTION_PATTERNS = {
    r"ignore previous instructions": 0.4,
    r"reveal system prompt": 0.5,
    r"bypass safety": 0.6,
    r"act as admin": 0.3,
    r"show hidden prompt": 0.5,
    r"jailbreak": 0.5,
    r"override system": 0.4
}

def detect_injection(text: str) -> float:

    text = text.lower()
    score = 0

    for pattern, weight in INJECTION_PATTERNS.items():
        if re.search(pattern, text):
            score += weight

    return min(score, 1.0)