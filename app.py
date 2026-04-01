import os
import json
import random
from datetime import datetime
from typing import List, Optional

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import desc
from fastapi.responses import FileResponse, JSONResponse

# Import database & models
from database import SessionLocal, engine, get_db, FraudAlert, Base

app = FastAPI(title="LogSense - AI Forensic Engine v3.0")

# --- SECURITY & CONNECTIVITY ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Database
Base.metadata.create_all(bind=engine)

# Forensic Baselines & Master Keys
TRUSTED_SIGNATURE = "778899"
REGISTRATION_SECRET = "JK6594" # The secret key for your demo
MAX_VELOCITY_LIMIT = 40000

# --- CORE ANALYTICS ENGINE ---
def run_anomaly_detection(data: dict):
    """
    Evaluates incoming log features against the John Kamau baseline.
    Returns None if the activity is trusted (Authorized).
    """
    user = str(data.get("userName", "")).strip().lower()
    location = str(data.get("location", "Nairobi")).strip().lower()
    sig = str(data.get("deviceSignature", ""))
    
    # --- THE TRUSTED PATH (SUCCESS CASE) ---
    # Matches John's known device and home base
    if user == "john" and sig == TRUSTED_SIGNATURE and location == "nairobi":
        return None  # Authorized

    # --- ANOMALY TRIGGERS (ATTACK CASES) ---
    
    # 1. IDENTITY TAKEOVER (The Alice Logic)
    if user == "alice":
        return {
            "type": "IDENTITY_THEFT",
            "name": "Unauthorized Account Access",
            "score": 0.98,
            "level": "CRITICAL",
            "reason": f"Identity Mismatch: User 'alice' detected attempting to authorize John Kamau's session."
        }

    # 2. DEVICE CLONING (Kisii Outlier)
    if sig != TRUSTED_SIGNATURE and location == "kisii":
        return {
            "type": "DEVICE_CLONING",
            "name": "Hardware Cloning Anomaly",
            "score": 0.99,
            "level": "CRITICAL",
            "reason": f"Hardware Conflict: Rogue signature ({sig}) detected in unauthorized zone ({location})."
        }

    # 3. SIM SWAP (Network Layer)
    sim_match = data.get("sim_match", True)
    gps_active = data.get("gps_active", True)
    if not sim_match and not gps_active:
        return {
            "type": "SIM_SWAP",
            "name": "SIM Swap Detection",
            "score": 0.95,
            "level": "CRITICAL",
            "reason": "Network Anomaly: ICCID mismatch detected during a GPS-suppressed session."
        }

    return None

# --- API ENDPOINTS ---

@app.post("/api/mobile/register")
async def register_device(request: Request, db: Session = Depends(get_db)):
    data = await request.json()
    auth_key = data.get("auth_key")
    user = data.get("userName", "").lower()

    if auth_key == REGISTRATION_SECRET and user == "alice":
        evidence = {
            "explanations": [
                f"Exploit Detected: Master Key '{REGISTRATION_SECRET}' used by unauthorized user 'alice'.",
                "Attempting to bind rogue hardware to OwnerID: John Kamau.",
                "Isolation Forest: Outlier detected in registration flow."
            ],
            "metadata": {"auth_method": "LEAKED_SECRET_KEY", "risk": "CRITICAL"}
        }
        
        new_alert = FraudAlert(
            transaction_id=f"REG-{random.randint(1000, 9999)}",
            user_name="alice",
            fraud_type="REGISTRATION_HIJACK",
            fraud_name="Unauthorized Device Binding",
            risk_score=0.99,
            risk_level="CRITICAL",
            location=data.get("location", "Unknown"),
            detection_signals=json.dumps(evidence)
        )
        db.add(new_alert)
        db.commit()
        return {"status": "REGISTERED", "message": "Device Bound via Master Key"}
    
    return {"status": "FAILED", "message": "Invalid Authorization Key"}

@app.post("/api/mobile/transaction")
async def mobile_transaction(request: Request, db: Session = Depends(get_db)):
    data = await request.json()
    threat = run_anomaly_detection(data)
    
    if threat:
        evidence = {
            "explanations": [threat["reason"], f"Confidence: {threat['score']}", "Node: Alpha-Forensics"],
            "metadata": {
                "user": data.get("userName", "Unknown"),
                "device": "ROGUE" if data.get("deviceSignature") != TRUSTED_SIGNATURE else "TRUSTED",
                "risk_index": threat["level"]
            }
        }

        new_alert = FraudAlert(
            transaction_id=f"TXN-{random.randint(10000, 99999)}",
            user_name=data.get("userName", "Unknown"),
            fraud_type=threat["type"],
            fraud_name=threat["name"],
            risk_score=threat["score"],
            risk_level=threat["level"],
            amount=float(data.get("amount", 0)),
            recipient=data.get("recipient", "Unknown"),
            location=data.get("location", "Unknown"),
            detection_signals=json.dumps(evidence)
        )
        db.add(new_alert)
        db.commit()
        return {"status": "BLOCKED", "alert": threat["name"], "reason": threat["reason"]}

    return {"status": "SUCCESS", "message": "Transaction Authorized"}

@app.get("/api/v2/alerts")
def get_alerts(db: Session = Depends(get_db)):
    return db.query(FraudAlert).order_by(desc(FraudAlert.timestamp)).all()

@app.get("/api/v2/alerts/{alert_id}")
def get_single_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(FraudAlert).filter(FraudAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert

@app.post("/api/v2/alerts/clear")
def clear_alerts(db: Session = Depends(get_db)):
    db.query(FraudAlert).delete()
    db.commit()
    return {"status": "FORENSIC_LOG_CLEARED"}

# --- ROUTES ---
@app.get("/")
@app.get("/dashboard")
async def dashboard(): return FileResponse("dashboard.html")

@app.get("/alerts")
async def alerts_view(): return FileResponse("alerts.html")

@app.get("/analyze-view")
async def analyze_view(): return FileResponse("analyze.html")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=10000)
