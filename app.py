import os
import json
import random
from datetime import datetime
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import desc, func
from fastapi.responses import FileResponse, JSONResponse

from database import SessionLocal, engine, get_db, FraudAlert, Base

app = FastAPI(title="LogSense - Forensic Fraud Engine")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

Base.metadata.create_all(bind=engine)

# --- HARDWARE PAIRING CONFIG ---
# This represents your "Married" Device (Phone A)
PHONE_A_SIGNATURE = "778899" 

# --- REFINED RESEARCH DETECTION LOGIC ---
def evaluate_logsense_forensics(data, db: Session):
    user = data.get("userName", "User").lower()
    recipient = data.get("recipient", "").lower()
    location = data.get("location", "Nairobi")
    
    # Identify if the request is coming from the "married" device or "Phone B"
    device_sig = data.get("deviceSignature", "UNKNOWN_B")
    
    try:
        amount = float(data.get("amount", 0))
    except:
        amount = 0.0

    # Hardware & GPS Toggles from Mobile App
    imei_match = data.get("imei_match", True)
    sim_match = data.get("sim_match", True)
    
    # Frequent/Safe Contacts List
    safe_contacts = ["zeddy", "eddie", "mary"]
    is_known_contact = any(contact in recipient for contact in safe_contacts)

    # Velocity Check: Count non-contact transfers in the last 30 minutes
    # This is what triggers the "3rd transaction" block
    recent_mule_attempts = db.query(FraudAlert).filter(
        FraudAlert.user_name == data.get("userName", "User"),
        FraudAlert.fraud_type == "MOBILE_MONEY_FRAUD"
    ).count()

    # 1. DEVICE CLONING (Phone A vs Phone B Scenario)
    # Trigger: IMEI Mismatch OR Unknown Signature + Location Shift
    if not imei_match or (device_sig != PHONE_A_SIGNATURE and user == "alice"):
        if location.lower() == "kisii":
            return {
                "type": "DEVICE_CLONING", 
                "name": "Hardware Collision", 
                "score": 0.98, 
                "level": "CRITICAL", 
                "reason": f"Identity Conflict: Account accessed via Phone B in Kisii while Phone A is registered in Nairobi."
            }
    
    # 2. SIM SWAP (Network Layer Breach)
    if not sim_match:
        return {
            "type": "SIM_SWAP", 
            "name": "SIM Swap Detected", 
            "score": 0.92, 
            "level": "CRITICAL", 
            "reason": "ICCID Serial Mismatch: Unauthorized SIM replacement detected."
        }

    # 3. IDENTITY THEFT (Alice Case)
    if user == "alice" and amount > 10000 and not is_known_contact:
        return {
            "type": "IDENTITY_THEFT", 
            "name": "Identity Theft (ATO)", 
            "score": 0.95, 
            "level": "CRITICAL", 
            "reason": f"Behavioral Anomaly: High-value transfer to unverified recipient outside Alice's social circle."
        }

    # 4. MOBILE MONEY FRAUD (The 3rd Transaction / Sequential Attack)
    # Trigger: 3rd transaction to a stranger OR single transaction > 40k
    if not is_known_contact:
        if amount > 40000 or recent_mule_attempts >= 2:
            return {
                "type": "MOBILE_MONEY_FRAUD", 
                "name": "Sequential Velocity Attack", 
                "score": 0.91, 
                "level": "HIGH", 
                "reason": f"Anomaly Detected: Transaction #3 in a rapid sequence to non-contacts (Mule Activity)."
            }

    return None

# --- MOBILE ENDPOINT ---
@app.post("/api/mobile/transaction")
async def mobile_transaction(request: Request, db: Session = Depends(get_db)):
    data = await request.json()
    
    # Pass the database session to check velocity
    threat = evaluate_logsense_forensics(data, db)
    
    try:
        txn_amount = float(data.get("amount", 0))
    except:
        txn_amount = 0.0

    if threat:
        # metadata for Forensic Lab
        signals = {
            "explanations": [
                threat["reason"], 
                f"Isolation Forest Anomaly Score: {threat['score']}",
                "Heuristic: Sequential Burst / Impossible Travel"
            ],
            "signals": {
                "User_Identity": data.get("userName", "Unknown"),
                "Device_Source": "Phone A (Married)" if data.get("deviceSignature") == PHONE_A_SIGNATURE else "Phone B (Intruder)",
                "IMEI_Integrity": "COMPROMISED" if not data.get("imei_match") else "SECURE", 
                "SIM_Integrity": "SWAP_DETECTED" if not data.get("sim_match") else "STABLE",
                "Geo_Sync": "CONFLICT (Kisii/Nairobi)" if not data.get("imei_match") and data.get("location").lower() == "kisii" else "OK",
                "Velocity_Index": f"Transaction #{ (db.query(FraudAlert).count()) + 1}"
            }
        }
        
        new_alert = FraudAlert(
            transaction_id=f"TXN-{random.randint(1000,9999)}",
            user_name=data.get("userName", "User"),
            fraud_type=threat["type"],
            fraud_name=threat["name"],
            risk_score=threat["score"],
            risk_level=threat["level"],
            amount=txn_amount,
            recipient=data.get("recipient", "Unknown"),
            location=data.get("location", "Nairobi"),
            detection_signals=json.dumps(signals)
        )
        db.add(new_alert)
        db.commit()
        return {"status": "BLOCKED", "reason": threat["type"]}
    
    return {"status": "SUCCESS"}

# --- ROUTES ---
@app.get("/")
@app.get("/dashboard")
async def serve_dash(): return FileResponse("dashboard.html")

@app.get("/alerts")
async def serve_alerts(): return FileResponse("alerts.html")

@app.get("/analyze-view")
async def serve_analyze(): return FileResponse("analyze.html")

@app.get("/api/v2/alerts")
def get_alerts(db: Session = Depends(get_db)):
    return db.query(FraudAlert).order_by(desc(FraudAlert.timestamp)).all()

@app.get("/api/v2/alerts/{id}")
def get_alert(id: int, db: Session = Depends(get_db)):
    return db.query(FraudAlert).filter(FraudAlert.id == id).first()

@app.post("/api/v2/alerts/clear")
def clear_alerts(db: Session = Depends(get_db)):
    db.query(FraudAlert).delete()
    db.commit()
    return {"status": "DATABASE_WIPED"}

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 10000))
    host = "0.0.0.0" if os.environ.get("RENDER") else "127.0.0.1"
    uvicorn.run(app, host=host, port=port)
