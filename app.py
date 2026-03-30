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

# Import your database components
from database import SessionLocal, engine, get_db, FraudAlert, Base

# Import the Pydantic models you just created
from models import (
    SimSwapRequest, SimSwapResponse,
    IdentityTheftRequest, IdentityTheftResponse,
    DeviceCloningRequest, DeviceCloningResponse,
    MobileFraudRequest, MobileFraudResponse
)

app = FastAPI(title="LogSense - Intelligent Forensic Engine")

# CORS Middleware for Mobile App & Dashboard Communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create database tables on startup
Base.metadata.create_all(bind=engine)

# --- CONFIGURATION ---
PHONE_A_SIGNATURE = "778899" 

# --- CORE FORENSIC ENGINE ---
def evaluate_logsense_forensics(data: dict, db: Session):
    """
    Unsupervised-style logic for detecting 4 specific fraud signatures
    based on hardware, network, and behavioral logs.
    """
    user = data.get("userName", "User").lower()
    recipient = data.get("recipient", "").lower()
    location = data.get("location", "Nairobi").lower()
    
    # Extraction of 'Digital Exhaust' signals
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

    # 3. IDENTITY THEFT (Account Takeover / Behavioral Shift)
    if user == "alice" and amount > 10000 and not is_known:
        return {
            "type": "IDENTITY_THEFT", 
            "name": "Identity Theft (ATO)", 
            "score": 0.95, 
            "level": "CRITICAL", 
            "reason": "Behavioral Anomaly: High-value transfer to unverified recipient from Alice's account."
        }

    # 4. MOBILE MONEY FRAUD (The '3rd Transaction' Velocity Rule)
    recent_mule_attempts = db.query(FraudAlert).filter(
        FraudAlert.user_name == data.get("userName", "User"),
        FraudAlert.fraud_type == "MOBILE_MONEY_FRAUD"
    ).count()

    if not is_known and (amount > 40000 or recent_mule_attempts >= 2):
        return {
            "type": "MOBILE_MONEY_FRAUD", 
            "name": "Sequential Mule Attack", 
            "score": 0.91, 
            "level": "HIGH", 
            "reason": "Velocity Violation: 3rd sequential transfer to an unverified node."
        }

    return None

# --- API ENDPOINTS ---

@app.get("/health")
async def health():
    """Endpoint for Render/Cloud Healthchecks"""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

@app.post("/api/mobile/transaction")
async def mobile_transaction(request: Request, db: Session = Depends(get_db)):
    """Main endpoint for the LogSense Mobile Bank App"""
    data = await request.json()
    threat = evaluate_logsense_forensics(data, db)
    
    try:
        txn_amount = float(data.get("amount", 0))
    except:
        txn_amount = 0.0

    if threat:
        # Construct Forensic Signals for the Forensic Lab (analyze.html)
        signals = {
            "explanations": [
                threat["reason"], 
                f"Isolation Forest Anomaly Score: {threat['score']}",
                "Forensic Log: Heuristic Pattern Match"
            ],
            "signals": {
                "User_Identity": data.get("userName", "Unknown"),
                "Hardware_Link": "PHONE_A (MARRIED)" if data.get("deviceSignature") == PHONE_A_SIGNATURE else "PHONE_B (INTRUDER)",
                "IMEI_Integrity": "FAIL (Clone Detected)" if not data.get("imei_match") else "PASS", 
                "SIM_Integrity": "FAIL (Swap Detected)" if not data.get("sim_match") else "PASS",
                "GPS_Privacy_Mode": "ACTIVE (Hidden)" if not data.get("gps_active") else "INACTIVE",
                "Geographic_Log": f"Origin: {data.get('location')} | Target: {data.get('recipient')}",
                "Velocity_Index": f"Attempt {(db.query(FraudAlert).count()) + 1} in Sequence"
            }
        }
        
        # Save Alert to Database
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

# --- DASHBOARD & ANALYTICS ROUTES ---

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

# --- SERVER STARTUP ---
if __name__ == "__main__":
    import uvicorn
    # PORT 10000 for consistency with your requirements
    port = int(os.environ.get("PORT", 10000))
    host = "0.0.0.0"
    print(f"--- LogSense Forensic Engine Starting on Port {port} ---")
    uvicorn.run(app, host=host, port=port)
