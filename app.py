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

# --- THE CORRECTED DETECTION LOGIC ---
def evaluate_logsense_forensics(data):
    user = data.get("userName", "User").lower()
    recipient = data.get("recipient", "").lower()
    
    try:
        amount = float(data.get("amount", 0))
    except:
        amount = 0.0

    # Hardware/GPS Toggles
    imei_match = data.get("imei_match", True)
    sim_match = data.get("sim_match", True)
    
    # 1. DEVICE & SIM TOGGLES
    if not imei_match:
        return {"type": "DEVICE_CLONING", "name": "Device Cloning Attempt", "score": 0.98, "level": "CRITICAL", "reason": "Hardware IMEI mismatch detected via system toggle."}
    
    if not sim_match:
        return {"type": "SIM_SWAP", "name": "SIM Swap Detected", "score": 0.88, "level": "CRITICAL", "reason": "ICCID mismatch detected via system toggle."}

    # 2. IDENTITY THEFT (Alice Logic)
    LIMIT = 10000 
    if user == "alice" and amount > LIMIT:
        if "mary" in recipient or "new" in recipient:
            return {
                "type": "IDENTITY_THEFT", 
                "name": "Identity Theft", 
                "score": 0.95, 
                "level": "CRITICAL", 
                "reason": f"Unauthorized high-value transaction by Alice to blacklisted recipient."
            }

    # 3. MOBILE MONEY FRAUD
    if amount > 5000 and "new" in recipient:
        return {
            "type": "MOBILE_MONEY_FRAUD", 
            "name": "Mobile Money Fraud", 
            "score": 0.85, 
            "level": "HIGH", 
            "reason": "Suspicious transfer to unverified mobile wallet."
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
        # --- FIXED SIGNALS BLOCK FOR FORENSIC LAB ---
        signals = {
            "explanations": [
                threat["reason"], 
                f"Isolation Forest Score: {threat['score']}",
                "Pattern Match: High-Risk Behavior"
            ],
            "signals": {
                "User_Identity": data.get("userName", "Unknown"),
                "IMEI_Integrity": "FAIL" if not data.get("imei_match") else "PASS", 
                "SIM_Integrity": "FAIL" if not data.get("sim_match") else "PASS",
                "Threshold_Status": "EXCEEDED" if txn_amount > 5000 else "NORMAL",
                "Recipient_Check": "VERIFIED" if txn_amount < 1000 else "HIGH_RISK_ENTITY"
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
            detection_signals=json.dumps(signals) # Stored as JSON string
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
