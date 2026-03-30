import requests
import time

# Update this with your Render URL or http://127.0.0.1:10000
BASE_URL = "http://127.0.0.1:10000" 
ENDPOINT = f"{BASE_URL}/api/mobile/transaction"

def trigger_test(name, data):
    print(f"--- Running: {name} ---")
    try:
        response = requests.post(ENDPOINT, json=data)
        print(f"Result: {response.json()}\n")
    except Exception as e:
        print(f"Error: Could not connect to server. Is app.py running? {e}")
    time.sleep(1)

# 0. SUCCESSFUL TRANSACTION (The "Control" Group)
# Scenario: Alice sends money to a known contact (Zeddy) from her married phone.
trigger_test("Scenario 0: Legitimate Transaction", {
    "userName": "Alice",
    "recipient": "Zeddy",
    "amount": 2500,
    "location": "Nairobi",
    "imei_match": True,
    "sim_match": True,
    "gps_active": True,
    "deviceSignature": "778899"
})

# 1. DEVICE CLONING (Phone B in Kisii)
trigger_test("Scenario 1: Device Cloning", {
    "userName": "Alice",
    "recipient": "Unknown_Hacker",
    "amount": 5000,
    "location": "Kisii",
    "imei_match": False,
    "sim_match": True,
    "gps_active": True,
    "deviceSignature": "UNKNOWN_B"
})

# 2. SIM SWAP (Dark Session / GPS Off)
trigger_test("Scenario 2: SIM Swap", {
    "userName": "Bob",
    "recipient": "Stranger_1",
    "amount": 2000,
    "location": "Nairobi",
    "imei_match": True,
    "sim_match": False,
    "gps_active": False,
    "deviceSignature": "778899"
})

# 3. IDENTITY THEFT (Alice Behavioral Anomaly)
trigger_test("Scenario 3: Identity Theft", {
    "userName": "Alice",
    "recipient": "Suspicious_Account",
    "amount": 15000,
    "location": "Nairobi",
    "imei_match": True,
    "sim_match": True,
    "gps_active": True,
    "deviceSignature": "778899"
})

# 4. MULE ATTACK (3rd Transaction Velocity)
for i in range(1, 4):
    trigger_test(f"Scenario 4: Mule Attempt {i}", {
        "userName": "Charlie",
        "recipient": f"Mule_Account_{i}",
        "amount": 5000,
        "location": "Nairobi",
        "imei_match": True,
        "sim_match": True,
        "gps_active": True,
        "deviceSignature": "778899"
    })
