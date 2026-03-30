import os
import json
import random
from datetime import datetime
from typing import List

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import desc
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

# Import database & models
from database import SessionLocal, engine, get_db, FraudAlert, Base

app = FastAPI(title="LogSense - Intelligent Forensic Engine")

# --- CONNECTIVITY CONFIG ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Database Tables
Base.metadata.create_all(bind=engine)

# Primary "Safe" Device Identifier for John Kamau
PHONE_A_SIGNATURE = "778899" 

# --- CORE FORENSIC ENGINE ---
def evaluate_logsense_forensics(data: dict, db: Session):
    """
    Analyzes 'Digital Exhaust' signals using rule-based forensics and 
    ML-simulated scoring to detect Identity Theft and Hardware Anomaly.
    """
    user = str(data.get("userName", "User")).strip().lower()
    recipient = str(data.get("recipient", "")).strip().lower()
    location = str(data.get("location", "Nairobi")).strip().lower()
    device_sig = data.get("deviceSignature", "UNKNOWN")

    imei_match = data.get("imei_match", True)
    sim_match = data.get("sim_match", True)
    gps_active = data.get("gps_active", True) 

    try:
        amount = float(data.get("amount", 0))
    except (ValueError, TypeError):
        amount = 0.0

    safe_contacts = ["zeddy", "eddie", "mary", "john"]
    is_known = any(contact in recipient for contact in safe_contacts)

    # 1. IDENTITY THEFT (The Alice vs. John Rule)
    if user == "alice":
        return {
            "type": "IDENTITY_THEFT", 
            "name": "Identity Theft (ATO)", 
            "score": 0.98, 
            "level": "CRITICAL", 
            "reason": "Unauthorized User: 'Alice' detected attempting to authorize a session linked to John Kamau."
        }

    # 2. DEVICE CLONING (Hardware Conflict + Geographic Anomaly)
    if device_sig != PHONE_A_SIGNATURE and location == "kisii":
        return {
            "type": "DEVICE_CLONING", 
            "name": "Hardware Cloning Anomaly", 
            "score": 0.99, 
            "level": "CRITICAL", 
            "reason": f"Hardware Conflict: Transaction from unrecognized signature ({device_sig}) in Kisii."
        }
    
    # 3. SIM SWAPPING (Network Swap + Privacy Masking)
    if not sim_match and not gps_active:
        return {
            "type": "SIM_SWAP", 
            "name": "SIM Swap (Dark Session)", 
            "score": 0.94, 
            "level": "CRITICAL", 
            "reason": "Network Anomaly: ICCID mismatch detected during a GPS-suppressed session."
        }

    # 4. MOBILE MONEY FRAUD (The Velocity / Mule Rule)
    if not is_known and amount >= 40000:
        return {
            "type": "MOBILE_MONEY_FRAUD", 
            "name": "High-Value Velocity Alert", 
            "score": 0.89, 
            "level": "HIGH", 
            "reason": f"Velocity Violation: Large transfer (KES {amount}) to an unverified recipient node."
        }

    return None

# --- API ENDPOINTS ---

@app.get("/")
@app.get("/dashboard")
async def serve_dash():
    # Ensures the dashboard loads even at the root URL
    return FileResponse("dashboard.html")

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "LogSense Engine", "node": "Render-Live"}

@app.post("/api/mobile/transaction")
async def mobile_transaction(request: Request, db: Session = Depends(get_db)):
    data = await request.json()
    threat = evaluate_logsense_forensics(data, db)
    
    try:
        txn_amount = float(data.get("amount", 0))
    except:
        txn_amount = 0.0

    if threat:
        signals = {
            "explanations": [
                threat["reason"], 
                f"Forensic Confidence Score: {threat['score']}",
                "LogSense ML Engine: Anomaly Isolated"
            ],
            "signals": {
                "Reported_User": data.get("userName", "Unknown"),
                "Device_Status": "AUTHORIZED" if data.get("deviceSignature") == PHONE_A_SIGNATURE else "ROGUE_DEVICE",
                "Hardware_Link": "Verified" if data.get("imei_match") else "IMEI_MISMATCH", 
                "Network_Layer": "Suspicious" if not data.get("sim_match") else "Trusted",
                "Location": f"{data.get('location')} -> {data.get('recipient')}",
                "Risk_Index": threat["level"]
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
        db.refresh(new_alert) 
        return {"status": "BLOCKED", "reason": threat["reason"]}
    
    return {"status": "SUCCESS"}

@app.get("/analyze-view")
async def serve_analyze():
    return FileResponse("analyze.html")

@app.get("/alerts")
async def serve_alerts():
    return FileResponse("alerts.html")

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
    uvicorn.run(app, host="0.0.0.0", port=port)
