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

# --- PATH CONFIGURATION ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# --- SECURITY & CONNECTIVITY ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def startup_event():
    Base.metadata.create_all(bind=engine)

TRUSTED_SIGNATURE = "778899"
REGISTRATION_SECRET = "JK6594" 

# --- CORE ANALYTICS ENGINE (Unchanged) ---
def run_anomaly_detection(data: dict):
    user = str(data.get("userName", "")).strip().lower()
    location = str(data.get("location", "Nairobi")).strip().lower()
    sig = str(data.get("deviceSignature", ""))
    sim_match = data.get("sim_match", True)
    
    if user == "john" and sig == TRUSTED_SIGNATURE and location == "nairobi":
        return None 

    if "alice" in user:
        return {
            "type": "IDENTITY_THEFT",
            "name": "Identity Theft Anomaly",
            "score": 0.99,
            "level": "CRITICAL",
            "reason": f"Identity Mismatch: User '{user}' attempted access on a session bound to Root Key {TRUSTED_SIGNATURE}."
        }

    if sig != TRUSTED_SIGNATURE and location == "kisii":
        return {
            "type": "DEVICE_CLONING",
            "name": "Hardware Cloning Anomaly",
            "score": 0.98,
            "level": "CRITICAL",
            "reason": f"Hardware Conflict: Rogue signature ({sig}) detected in restricted zone ({location})."
        }

    if not sim_match:
        return {
            "type": "SIM_SWAP",
            "name": "Network Integrity Anomaly",
            "score": 0.95,
            "level": "HIGH",
            "reason": "Security Alert: Subscriber Identity Module (SIM) mismatch detected during transaction."
        }
    return None

# --- API ENDPOINTS ---

@app.post("/api/mobile/transaction")
async def mobile_transaction(request: Request, db: Session = Depends(get_db)):
    data = await request.json()
    threat = run_anomaly_detection(data)
    
    if threat:
        forensic_payload = {
            "explanations": [
                threat["reason"],
                f"Isolation Forest Confidence: {threat['score']}",
                f"Detection Node: {request.client.host if request.client else 'Remote'}"
            ],
            "signals": {
                "Reported_User": data.get("userName", "Unknown"),
                "Device_Signature": data.get("deviceSignature", "Unknown"),
                "Network_IP": request.client.host if request.client else "0.0.0.0",
                "Geo_Location": data.get("location", "Unknown"),
                "System_Status": "ROGUE_INTERCEPTED"
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
            recipient=data.get("recipient", "Internal Node"),
            location=data.get("location", "Nairobi"),
            detection_signals=json.dumps(forensic_payload)
        )
        db.add(new_alert)
        db.commit()
        return {"status": "BLOCKED", "alert": threat["name"], "reason": threat["reason"]}

    return {"status": "SUCCESS", "message": "Authorized"}

@app.get("/api/v2/alerts")
def get_alerts(db: Session = Depends(get_db)):
    return db.query(FraudAlert).order_by(desc(FraudAlert.timestamp)).all()

@app.get("/api/v2/alerts/{alert_id}")
def get_alert_detail(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(FraudAlert).filter(FraudAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert

# --- NEW: WIPE DATABASE FUNCTIONALITY ---
@app.post("/api/v2/alerts/clear")
def clear_alerts(db: Session = Depends(get_db)):
    try:
        db.query(FraudAlert).delete()
        db.commit()
        return {"message": "Database wiped successfully"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

# --- ROUTING SYSTEM ---

@app.get("/")
@app.get("/dashboard")
async def dashboard_page(): 
    return FileResponse(os.path.join(BASE_DIR, "dashboard.html"))

@app.get("/alerts")
async def alerts_page(): 
    return FileResponse(os.path.join(BASE_DIR, "alerts.html"))

# Added /analyze-view to match your HTML Sidebar links
@app.get("/analyze-view")
@app.get("/analyze")
async def analyze_page(): 
    path = os.path.join(BASE_DIR, "analyze.html")
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="analyze.html not found")
    return FileResponse(path)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=10000)
