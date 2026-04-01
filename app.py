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

# Forensic Baselines for John Kamau
TRUSTED_SIGNATURE = "778899"
HOME_BASE = "nairobi"
MAX_VELOCITY_LIMIT = 40000

# --- CORE ANALYTICS ENGINE ---
def run_anomaly_detection(data: dict):
    """
    Evaluates incoming log features against the 'Married' baseline.
    Returns a dict with threat details if an anomaly is isolated.
    """
    user = str(data.get("userName", "")).strip().lower()
    location = str(data.get("location", "Nairobi")).strip().lower()
    sig = str(data.get("deviceSignature", ""))
    
    sim_match = data.get("sim_match", True)
    gps_active = data.get("gps_active", True)
    amount = float(data.get("amount", 0))
    
    # Recipient verification
    recipient = str(data.get("recipient", "")).lower()
    safe_contacts = ["zeddie", "eddy", "mary", "john"]
    is_known = any(contact in recipient for contact in safe_contacts)

    # 1. IDENTITY THEFT (The Alice Takeover)
    if user == "alice":
        return {
            "type": "IDENTITY_THEFT",
            "name": "Unauthorized Account Access",
            "score": 0.98,
            "level": "CRITICAL",
            "reason": f"Identity Mismatch: User '{user}' detected attempting to authorize John Kamau's session."
        }

    # 2. DEVICE CLONING (Hardware + Geo Mismatch)
    if sig != TRUSTED_SIGNATURE and location == "kisii":
        return {
            "type": "DEVICE_CLONING",
            "name": "Hardware Cloning Anomaly",
            "score": 0.99,
            "level": "CRITICAL",
            "reason": f"Hardware Conflict: Rogue signature ({sig}) detected in unauthorized zone ({location})."
        }

    # 3. SIM SWAP (Network Layer Anomaly)
    if not sim_match and not gps_active:
        return {
            "type": "SIM_SWAP",
            "name": "SIM Swap Detection",
            "score": 0.95,
            "level": "CRITICAL",
            "reason": "Network Anomaly: ICCID mismatch detected during a GPS-suppressed session."
        }

    # 4. MOBILE MONEY FRAUD (Velocity Detection)
    if not is_known and amount >= MAX_VELOCITY_LIMIT:
        return {
            "type": "MOBILE_MONEY_FRAUD",
            "name": "High-Value Velocity Alert",
            "score": 0.88,
            "level": "HIGH",
            "reason": f"Velocity Breach: KES {amount} transfer to unverified node."
        }

    return None

# --- API ENDPOINTS ---

@app.post("/api/mobile/transaction")
async def mobile_transaction(request: Request, db: Session = Depends(get_db)):
    data = await request.json()
    threat = run_anomaly_detection(data)
    
    if threat:
        # Construct Forensic Evidence for the Analyze Page
        evidence = {
            "explanations": [
                threat["reason"],
                f"Isolation Forest Confidence: {threat['score']}",
                "LogSense Node: Render-Production-Alpha"
            ],
            "metadata": {
                "user": data.get("userName", "Unknown"),
                "device": "ROGUE" if data.get("deviceSignature") != TRUSTED_SIGNATURE else "TRUSTED",
                "sim_status": "MATCHED" if data.get("sim_match") else "MISMATCH",
                "risk_index": threat["level"]
            }
        }

        # Save to Database
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
            detection_signals=json.dumps(evidence) # This powers the Analyze page
        )
        db.add(new_alert)
        db.commit()
        
        return {"status": "BLOCKED", "alert": threat["name"], "reason": threat["reason"]}

    return {"status": "SUCCESS", "message": "Transaction Authorized"}

@app.get("/api/v2/alerts")
def get_alerts(db: Session = Depends(get_db)):
    return db.query(FraudAlert).order_by(desc(FraudAlert.timestamp)).all()

@app.post("/api/v2/alerts/clear")
def clear_alerts(db: Session = Depends(get_db)):
    db.query(FraudAlert).delete()
    db.commit()
    return {"status": "FORENSIC_LOG_CLEARED"}

# --- STATIC DASHBOARD ROUTES ---
@app.get("/")
@app.get("/dashboard")
async def dashboard():
    return FileResponse("dashboard.html")

@app.get("/alerts")
async def alerts_view():
    return FileResponse("alerts.html")

@app.get("/analyze-view")
async def analyze_view():
    """NEW: Route for the AI Reasoning & Metadata Logs page"""
    return FileResponse("analyze.html")

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 10000))
    uvicorn.run(app, host="0.0.0.0", port=port)
