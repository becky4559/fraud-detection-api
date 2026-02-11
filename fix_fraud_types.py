# Create a fixed fraud types response
fraud_types_data = {
    "sim_swap": {"severity": "CRITICAL", "description": "Unauthorized SIM card replacement"},
    "agent_collusion": {"severity": "HIGH", "description": "Agent working with fraudsters"},
    "social_engineering": {"severity": "HIGH", "description": "Manipulating users to reveal information"},
    "identity_theft": {"severity": "CRITICAL", "description": "Stealing personal identity information"},
    "mobile_money_fraud": {"severity": "HIGH", "description": "Fraudulent mobile money transactions"},
    "repayment_fraud": {"severity": "MEDIUM", "description": "False repayment claims"},
    "synthetic_identity": {"severity": "HIGH", "description": "Creating fake identities from real data"},
    "device_cloning": {"severity": "CRITICAL", "description": "Cloning mobile devices for fraud"}
}

types_list = []
for name, info in fraud_types_data.items():
    types_list.append({
        "name": name,
        "severity": info["severity"],
        "description": info["description"]
    })

print(f'Fixed response format:')
print(f'{{"total": {len(types_list)}, "types": [')
for item in types_list:
    print(f'  {{"name": "{item["name"]}", "severity": "{item["severity"]}", "description": "{item["description"]}"}},')
print(']}')
