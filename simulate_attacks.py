import requests
import time

# Update to your Render URL: e.g., "https://logsense-engine.onrender.com"
BASE_URL = "http://127.0.0.1:10000" 
ENDPOINT = f"{BASE_URL}/api/mobile/transaction"

def trigger_test(name, data):
    print(f"--- Running: {name} ---")
    try:
        response = requests.post(ENDPOINT, json=data)
        result = response.json()
        status = result.get("status")
        reason = result.get("reason", "N/A")
        print(f"Result: {status} | Reason: {reason}\n")
    except Exception as e:
        print(f"Error: Could not connect to server. {e}")
    time.sleep(1)

# 0. SUCCESSFUL TRANSACTION
# Logic: Name is NOT Alice, signature is 778899, amount is low.
trigger_test("Scenario 0: Legitimate Transaction (John)", {
    "userName": "John",
    "recipient": "zeddie",
    "amount": 2500,
    "location": "Nairobi",
    "imei_match": True,
    "sim_match": True,
    "gps_active": True,
    "deviceSignature": "778899"
})

# 1. DEVICE CLONING
# Logic: Wrong signature + Kisii location.
trigger_test("Scenario 1: Device Cloning", {
    "userName": "John",
    "recipient": "Unknown_Hacker",
    "amount": 5000,
    "location": "Kisii",
    "imei_match": False,
    "sim_match": True,
    "gps_active": True,
    "deviceSignature": "UNKNOWN_B"
})

# 2. SIM SWAP
# Logic: sim_match=False and gps_active=False.
trigger_test("Scenario 2: SIM Swap", {
    "userName": "John",
    "recipient": "Stranger_1",
    "amount": 2000,
    "location": "Nairobi",
    "imei_match": True,
    "sim_match": False,
    "gps_active": False,
    "deviceSignature": "778899"
})

# 3. IDENTITY THEFT (The Alice Takeover)
# Logic: userName="alice" is a hard-coded CRITICAL alert.
trigger_test("Scenario 3: Identity Theft (Alice)", {
    "userName": "alice",
    "recipient": "Suspicious_Account",
    "amount": 15000,
    "location": "Nairobi",
    "imei_match": True,
    "sim_match": True,
    "gps_active": True,
    "deviceSignature": "778899"
})

# 4. MULE ATTACK (Velocity Breach)
# Logic: Amount > 40,000 and unknown recipient.
trigger_test("Scenario 4: High-Value Velocity", {
    "userName": "John",
    "recipient": "Mule_Account_99",
    "amount": 45000,
    "location": "Nairobi",
    "imei_match": True,
    "sim_match": True,
    "gps_active": True,
    "deviceSignature": "778899"
})
