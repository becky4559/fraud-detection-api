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

# Import database & models - Ensure these files exist in your directory
from database import SessionLocal, engine, get_db, FraudAlert, Base
from models import (
    SimSwapRequest, SimSwapResponse,
    IdentityTheftRequest, IdentityTheftResponse,
    DeviceCloningRequest, DeviceCloningResponse,
    MobileFraudRequest, MobileFraudResponse
)

app = FastAPI(title="LogSense - Intelligent Forensic Engine")

# --- CONNECTIVITY CONFIG ---
# Allows Dashboard (Browser) and Mobile App to communicate with the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Database Tables
Base.metadata.create_all(bind=engine)

# Primary "Safe" Device Identifier
PHONE_A_SIGNATURE = "778899" 

# --- CORE FORENSIC ENGINE ---
def evaluate_logsense_forensics(data: dict, db: Session):
    """
    Simulates an Isolation Forest (Unsupervised ML) detection engine.
    Analyzes system logs for hardware, network, and behavioral anomalies.
    """
    # Normalize inputs to prevent case-sensitivity demo fails
    user = str(data.get("userName", "User")).strip().lower()
    recipient = str(data.get("recipient", "")).strip().lower()
    location = str(data.get("location", "Nairobi")).strip().lower()
    
    # Extract Digital Exhaust signals
    imei_match = data.get("imei_match", True)
    sim_match = data.get("sim_match", True)
    gps_active = data.get("gps_active", True) 
    device_sig = data.get("deviceSignature", "UNKNOWN_B")

    try:
        amount = float(data.get("amount", 0))
    except (ValueError, TypeError):
        amount = 0.0

    # Social Graph validation
    safe_contacts = ["zeddy", "eddie", "mary"]
    is_known = any(contact in recipient for contact in safe_contacts)

    # 1. DEVICE CLONING (Hardware Conflict + Impossible Travel)
    if not imei_match and location == "kisii":
        return {
            "type": "DEVICE_CLONING", 
            "name": "Impossible Travel (Cloning)", 
            "score": 0.99, 
            "level": "CRITICAL", 
            "reason": "Hardware Conflict: Account accessed via unauthorized Phone B in Kisii."
        }
    
    # 2. SIM SWAPPING (Network Swap + Privacy Masking)
    if not sim_match and not gps_active:
        return {
            "type": "SIM_SWAP", 
            "name": "SIM Swap (Dark Session)", 
            "score": 0.94, 
            "level": "CRITICAL", 
            "reason": "Network Anomaly: ICCID mismatch detected during a GPS-suppressed session."
        }

    # 3. IDENTITY THEFT (Behavioral Anomaly - The Alice Rule)
    if user == "alice" and amount > 10000 and not is_known:
        return {
            "type": "IDENTITY_THEFT", 
            "name": "Identity Theft (ATO)", 
            "score": 0.95, 
            "level": "CRITICAL", 
            "reason": f"Behavioral Anomaly: Alice sending high-value {amount} to unverified recipient {recipient}."
        }

    # 4. MOBILE MONEY FRAUD (The Velocity / Mule Rule)
    recent_mule_attempts = db.query(FraudAlert).filter(
        FraudAlert.user_name.ilike(user),
        FraudAlert.fraud_type == "MOBILE_MONEY_FRAUD"
    ).count()

    if not is_known and (amount >= 40000 or recent_mule_attempts >= 2):
        return {
            "type": "MOBILE_MONEY_FRAUD", 
            "name": "Sequential Mule Attack", 
            "score": 0.91, 
            "level": "HIGH", 
            "reason": "Velocity Violation: High-value or 3rd sequential transfer to an unverified node."
        }

    return None

# --- API ENDPOINTS ---

@app.get("/health")
async def health():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

@app.post("/api/mobile/transaction")
async def mobile_transaction(request: Request, db: Session = Depends(get_db)):
    data = await request.json()
    threat = evaluate_logsense_forensics(data, db)
    
    try:
        txn_amount = float(data.get("amount", 0))
    except:
        txn_amount = 0.0

    if threat:
        # Build the forensic 'Explanations' for the Analyze View (XAI)
        signals = {
            "explanations": [
                threat["reason"], 
                f"Isolation Forest Score: {threat['score']}",
                "Forensic Log: Pattern Matched"
            ],
            "signals": {
                "User_Identity": data.get("userName", "Unknown"),
                "Hardware_Link": "PHONE_A" if data.get("deviceSignature") == PHONE_A_SIGNATURE else "PHONE_B (INTRUDER)",
                "IMEI_Integrity": "FAIL" if not data.get("imei_match") else "PASS", 
                "SIM_Integrity": "FAIL" if not data.get("sim_match") else "PASS",
                "GPS_Status": "HIDDEN" if not data.get("gps_active") else "VISIBLE",
                "Geographic_Log": f"{data.get('location')} -> {data.get('recipient')}",
                "Velocity_Index": f"Alert #{db.query(FraudAlert).count() + 1}"
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
        return {"status": "BLOCKED", "reason": threat["type"]}
    
    return {"status": "SUCCESS"}

# --- DASHBOARD & ANALYTICS ---

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
    # Use Port 10000 for consistency across all files
    port = int(os.environ.get("PORT", 10000))
    uvicorn.run(app, host="0.0.0.0", port=port)
