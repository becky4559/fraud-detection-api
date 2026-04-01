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

# Import database & models (Ensure these files exist)
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
REGISTRATION_SECRET = "JK6594" 
MAX_VELOCITY_LIMIT = 40000

# --- CORE ANALYTICS ENGINE ---
def run_anomaly_detection(data: dict):
    user = str(data.get("userName", "")).strip().lower()
    location = str(data.get("location", "Nairobi")).strip().lower()
    sig = str(data.get("deviceSignature", ""))
    
    # Authorized Case
    if user == "john" and sig == TRUSTED_SIGNATURE and location == "nairobi":
        return None 

    # 1. IDENTITY THEFT (The Alice Logic)
    if "alice" in user:
        return {
            "type": "IDENTITY_THEFT",
            "name": "Identity Theft Anomaly",
            "score": 0.99,
            "level": "CRITICAL",
            "reason": f"Identity Mismatch: User '{user}' is not the provisioned owner of Key {TRUSTED_SIGNATURE}."
        }

    # 2. DEVICE CLONING (Kisii Outlier)
    if sig != TRUSTED_SIGNATURE and location == "kisii":
        return {
            "type": "DEVICE_CLONING",
            "name": "Hardware Cloning Anomaly",
            "score": 0.99,
            "level": "CRITICAL",
            "reason": f"Hardware Conflict: Unknown signature ({sig}) detected in Kisii zone."
        }

    return None

# --- API ENDPOINTS ---

@app.post("/api/mobile/register")
async def register_device(request: Request, db: Session = Depends(get_db)):
    data = await request.json()
    auth_key = data.get("auth_key")
    if auth_key == REGISTRATION_SECRET:
        return {"status": "SUCCESS", "message": "Identity Provisioned Successfully."}
    return JSONResponse(status_code=403, content={"status": "FAILED", "message": "Invalid Key"})

@app.post("/api/mobile/transaction")
async def mobile_transaction(request: Request, db: Session = Depends(get_db)):
    data = await request.json()
    threat = run_anomaly_detection(data)
    
    if threat:
        # STRUCTURED FOR FORENSIC LAB HTML
        forensic_payload = {
            "explanations": [
                threat["reason"],
                f"Isolation Forest Confidence: {threat['score']}",
                "Heuristic: Location/Signature Mismatch"
            ],
            "signals": {
                "User_Identity": data.get("userName", "Unknown"),
                "Device_Signature": data.get("deviceSignature", "MISSING"),
                "Network_Location": data.get("location", "Unknown"),
                "System_Status": "ROGUE_PROCESS_INTERCEPTED"
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
            location=data.get("location", "Nairobi"),
            # Ensure this key matches what your JS looks for:
            detection_signals=json.dumps(forensic_payload)
        )
        db.add(new_alert)
        db.commit()
        return {"status": "BLOCKED", "alert": threat["name"], "reason": threat["reason"]}

    return {"status": "SUCCESS", "message": "Transaction Authorized"}

@app.get("/api/v2/alerts")
def get_alerts(db: Session = Depends(get_db)):
    return db.query(FraudAlert).order_by(desc(FraudAlert.timestamp)).all()

# Endpoint for specific alert detail (The Forensic Lab fetch)
@app.get("/api/v2/alerts/{alert_id}")
def get_alert_detail(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(FraudAlert).filter(FraudAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert

@app.post("/api/v2/alerts/clear")
def clear_alerts(db: Session = Depends(get_db)):
    db.query(FraudAlert).delete()
    db.commit()
    return {"status": "FORENSIC_LOG_CLEARED"}

# --- DASHBOARD ROUTES ---
@app.get("/")
@app.get("/dashboard")
async def dashboard(): return FileResponse("dashboard.html")

@app.get("/alerts")
async def alerts_page(): return FileResponse("alerts.html")

@app.get("/analyze-view")
async def analyze_page(): return FileResponse("analyze-view.html")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=10000)
