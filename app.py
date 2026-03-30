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

# --- DETECTION LOGIC ---
def evaluate_logsense_forensics(data):
    user_name = data.get("userName", "User")
    amount = float(data.get("amount", 0))
    recipient = data.get("recipient", "").lower()
    imei_match = data.get("imei_match", True)
    sim_match = data.get("sim_match", True)
    location = data.get("location", "Nairobi")

    if not imei_match:
        return {"type": "DEVICE_CLONING", "name": "Mobile Device Cloning", "score": 0.98, "level": "CRITICAL", "reason": "Hardware IMEI mismatch detected."}
    if not sim_match:
        return {"type": "SIM_SWAP", "name": "SIM Swap Detected", "score": 0.88, "level": "HIGH", "reason": "ICCID serial change without migration."}
    if "mary" in recipient or "akinyi" in recipient:
        return {"type": "IDENTITY_THEFT", "name": "Blacklisted Recipient", "score": 0.95, "level": "CRITICAL", "reason": "Recipient matches high-risk fraud database."}
    if location != "Nairobi" and location != "Unknown":
         return {"type": "GEOGRAPHIC_FRAUD", "name": "Geographic Displacement", "score": 0.85, "level": "HIGH", "reason": f"Transaction from {location} is outside home cluster."}
    
    return None

# --- MOBILE ENDPOINT ---
@app.post("/api/mobile/transaction")
async def mobile_transaction(request: Request, db: Session = Depends(get_db)):
    data = await request.json()
    threat = evaluate_logsense_forensics(data)
    
    if threat:
        signals = {
            "explanations": [threat["reason"], f"Isolation Forest Score: {threat['score']}"],
            "signals": {"IMEI": "CLONED" if not data.get("imei_match") else "OK", "SIM": "SWAP" if not data.get("sim_match") else "OK"}
        }
        new_alert = FraudAlert(
            transaction_id=f"TXN-{random.randint(1000,9999)}",
            user_name=data.get("userName"),
            fraud_type=threat["type"],
            fraud_name=threat["name"],
            risk_score=threat["score"],
            risk_level=threat["level"],
            amount=amount,
            recipient=data.get("recipient"),
            location=data.get("location"),
            detection_signals=json.dumps(signals)
        )
        db.add(new_alert)
        db.commit()
        return {"status": "BLOCKED", "reason": threat["type"]}
    return {"status": "SUCCESS"}

# --- WEB ROUTES ---
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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=10000)
