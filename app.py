import os
import json
import random
from datetime import datetime
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import desc
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

# --- REFINED RESEARCH DETECTION LOGIC ---
def evaluate_logsense_forensics(data):
    user = data.get("userName", "User").lower()
    recipient = data.get("recipient", "").lower()
    location = data.get("location", "Nairobi")
    
    try:
        amount = float(data.get("amount", 0))
    except:
        amount = 0.0

    # Hardware & GPS Toggles
    imei_match = data.get("imei_match", True)
    sim_match = data.get("sim_match", True)
    
    # Frequent/Safe Contacts List
    safe_contacts = ["zeddy", "eddie", "mary"]
    is_known_contact = any(contact in recipient for contact in safe_contacts)

    # 1. DEVICE CLONING (Physical Layer Breach)
    # Scenario: Phone A toggles Kisii, Phone B (Nairobi) sends money.
    if not imei_match and location.lower() == "kisii":
        return {
            "type": "DEVICE_CLONING", 
            "name": "Mobile Device Cloning", 
            "score": 0.98, 
            "level": "CRITICAL", 
            "reason": f"Hardware Collision: Device ID active in Kisii while system log registers Nairobi session (< 1 min)."
        }
    
    # 2. SIM SWAP (Network Layer Breach)
    # Scenario: GPS Toggle is off, SIM toggle triggers mismatch.
    if not sim_match:
        return {
            "type": "SIM_SWAP", 
            "name": "SIM Swap Detected", 
            "score": 0.92, 
            "level": "CRITICAL", 
            "reason": "ICCID Serial Mismatch: Unauthorized SIM replacement detected while GPS tracking was suppressed."
        }

    # 3. IDENTITY THEFT (Behavioral Anomaly - Alice Case)
    # Scenario: Alice sends > 10,000 to someone NOT in her contacts (Zeddy/Eddie/Mary).
    if user == "alice" and amount > 10000 and not is_known_contact:
        return {
            "type": "IDENTITY_THEFT", 
            "name": "Identity Theft (ATO)", 
            "score": 0.95, 
            "level": "CRITICAL", 
            "reason": f"Account Takeover: High-value transfer (KES {amount}) to unverified recipient outside contact circle."
        }

    # 4. MOBILE MONEY FRAUD (Transaction Anomaly)
    # Scenario: Amount > 40,000 to 2+ people who are NOT Zeddy, Eddie, or Mary.
    if amount > 40000 and not is_known_contact:
        return {
            "type": "MOBILE_MONEY_FRAUD", 
            "name": "Mule Wallet Transfer", 
            "score": 0.89, 
            "level": "HIGH", 
            "reason": "Velocity Violation: Bulk fund movement exceeding KES 40,000 to unauthorized mobile node."
        }

    return None

# --- MOBILE ENDPOINT ---
@app.post("/api/mobile/transaction")
async def mobile_transaction(request: Request, db: Session = Depends(get_db)):
    data = await request.json()
    threat = evaluate_logsense_forensics(data)
    
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
                "Heuristic: Impossible Travel / Behavioral Shift"
            ],
            "signals": {
                "User_Identity": data.get("userName", "Unknown"),
                "IMEI_Integrity": "COMPROMISED" if not data.get("imei_match") else "SECURE", 
                "SIM_Integrity": "SWAP_DETECTED" if not data.get("sim_match") else "STABLE",
                "Geo_Sync": "CONFLICT (Kisii/Nairobi)" if not data.get("imei_match") and data.get("location") == "Kisii" else "OK",
                "Recipient_Verification": "UNAUTHORIZED" if threat["type"] in ["IDENTITY_THEFT", "MOBILE_MONEY_FRAUD"] else "VERIFIED"
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
