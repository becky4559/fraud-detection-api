import re

with open('app.py', 'r') as f:
    content = f.read()

# Replace the fraud_types function
old_function = '''def fraud_types():
    return {
        "total": 8,
        "types": [
            "sim_swap",
            "agent_collusion",
            "social_engineering",
            "identity_theft",
            "mobile_money_fraud",
            "repayment_fraud",
            "synthetic_identity",
            "device_cloning"
        ]
    }'''

new_function = '''def fraud_types():
    fraud_types_data = [
        {"name": "sim_swap", "severity": "CRITICAL", "description": "Unauthorized SIM card replacement"},
        {"name": "agent_collusion", "severity": "HIGH", "description": "Agent working with fraudsters"},
        {"name": "social_engineering", "severity": "HIGH", "description": "Manipulating users to reveal information"},
        {"name": "identity_theft", "severity": "CRITICAL", "description": "Stealing personal identity information"},
        {"name": "mobile_money_fraud", "severity": "HIGH", "description": "Fraudulent mobile money transactions"},
        {"name": "repayment_fraud", "severity": "MEDIUM", "description": "False repayment claims"},
        {"name": "synthetic_identity", "severity": "HIGH", "description": "Creating fake identities from real data"},
        {"name": "device_cloning", "severity": "CRITICAL", "description": "Cloning mobile devices for fraud"}
    ]
    return {
        "total": len(fraud_types_data),
        "types": fraud_types_data
    }'''

# Replace in content
if old_function in content:
    content = content.replace(old_function, new_function)
    print("✅ Function updated successfully!")
else:
    print("❌ Could not find exact function match. Let me try another approach...")
    # Try to find and replace just the array
    content = re.sub(r'"types": \[\s*"[^"]+"(?:,\s*"[^"]+")*\s*\]', '"types": fraud_types_data', content)
    # Add the fraud_types_data variable at the beginning of the function
    content = re.sub(r'def fraud_types\(\):\s*return {', '''def fraud_types():
    fraud_types_data = [
        {"name": "sim_swap", "severity": "CRITICAL", "description": "Unauthorized SIM card replacement"},
        {"name": "agent_collusion", "severity": "HIGH", "description": "Agent working with fraudsters"},
        {"name": "social_engineering", "severity": "HIGH", "description": "Manipulating users to reveal information"},
        {"name": "identity_theft", "severity": "CRITICAL", "description": "Stealing personal identity information"},
        {"name": "mobile_money_fraud", "severity": "HIGH", "description": "Fraudulent mobile money transactions"},
        {"name": "repayment_fraud", "severity": "MEDIUM", "description": "False repayment claims"},
        {"name": "synthetic_identity", "severity": "HIGH", "description": "Creating fake identities from real data"},
        {"name": "device_cloning", "severity": "CRITICAL", "description": "Cloning mobile devices for fraud"}
    ]
    return {''', content)

# Write back to file
with open('app.py', 'w') as f:
    f.write(content)

print("✅ Updated app.py with new fraud types format")
