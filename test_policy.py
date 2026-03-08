from app.policy_engine import policy_decision

# example scenarios

print(policy_decision(0.9, []))   # expected BLOCK
print(policy_decision(0.5, []))   # expected MASK
print(policy_decision(0.1, ["PII"]))  # expected MASK
print(policy_decision(0.1, []))   # expected ALLOW