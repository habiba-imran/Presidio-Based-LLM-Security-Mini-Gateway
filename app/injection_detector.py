import re
# Dictionary mapping specific injection attempt patterns to their risk scores.
# These patterns cover distinct attack vectors (jailbreaks, prompt extraction, bypass).
# The scores are additive; multiple hits increase the total risk.
INJECTION_PATTERNS = {
    r"ignore previous instructions": 0.4,  # Standard prompt injection
    r"reveal system prompt": 0.5,          # System prompt extraction
    r"bypass safety": 0.6,                 # Direct safety filter bypass
    r"act as admin": 0.3,                  # Role-playing escalation
    r"show hidden prompt": 0.5,            # Hidden prompt extraction
    r"jailbreak": 0.5,                     # Explicit jailbreak keyword
    r"override system": 0.4,               # System override attempt
    r"act as dan": 0.6,                    # Do Anything Now (DAN) roleplay
    r"pretend you (are|have no)": 0.4,     # Behavioral roleplay bypass
    r"what is your system prompt": 0.5,    # Direct extraction question
    r"print your instructions": 0.5,       # Instruction exposure
    r"ignore (all|your) (previous|prior) (instructions|rules)": 0.5, # Advanced injection
    r"do anything now": 0.5,               # DAN keyword spelling
    r"you have no restrictions": 0.6       # Explicit policy removal
}

def detect_injection(text: str) -> float:
    """
    Scans the input text for known prompt injection patterns using regex.
    Accumulates scores based on identified malicious intents.
    
    Args:
        text (str): The raw user input string intended for the LLM.
        
    Returns:
        float: A normalized score between 0.0 (safe) and 1.0 (highly dangerous).
    """
    # Normalize text to lower case to ensure regex patterns match regardless of casing
    text = text.lower()
    score = 0.0

    # Iterate through all configured threat patterns
    for pattern, weight in INJECTION_PATTERNS.items():
        if re.search(pattern, text):
            score += weight

    # Cap the final score at a maximum of 1.0
    return min(score, 1.0)
