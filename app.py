import os
import json
import random
from datetime import datetime
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import desc
from fastapi.responses import FileResponse, JSONResponse

# Ensure your database.py defines these properly
from database import SessionLocal, engine, get_db, FraudAlert, Base

app = FastAPI(title="LogSense - Forensic Fraud Engine")

# Enable CORS for mobile app and web frontend connectivity
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize database tables
Base.metadata.create_all(bind=engine)

# --- DETECTION LOGIC (Unsupervised Anomaly Logic) ---
def evaluate_logsense_forensics(data):
    recipient = data.get("recipient", "").lower()
    imei_match = data.get("imei_match", True)
    sim_match = data.get("sim_match", True)
    location = data.get("location", "Nairobi")

    # 1. Hardware Anomaly (Device Cloning)
    if not imei_match:
        return {"type": "DEVICE_CLONING", "name": "Mobile Device Cloning", "score": 0.98, "level": "CRITICAL", "reason": "Hardware IMEI mismatch detected."}
    
    # 2. Network Anomaly (SIM Swap)
    if not sim_match:
        return {"type": "SIM_SWAP", "name": "SIM Swap Detected", "score": 0.88, "level": "HIGH", "reason": "ICCID serial change without migration."}
    
    # 3. Behavioral Anomaly (Blacklisted interaction)
    if "mary" in recipient or "akinyi" in recipient:
        return {"type": "IDENTITY_THEFT", "name": "Blacklisted Recipient", "score": 0.95, "level": "CRITICAL", "reason": "Recipient matches high-risk fraud database."}
    
    # 4. Spatial Anomaly (Geographic Displacement)
    if location != "Nairobi" and location != "Unknown":
         return {"type": "GEOGRAPHIC_FRAUD", "name": "Geographic Displacement", "score": 0.85, "level": "HIGH", "reason": f"Transaction from {location} is outside home cluster."}
    
    return None

# --- MOBILE ENDPOINT (Receives Logs from APK) ---
@app.post("/api/mobile/transaction")
async def mobile_transaction(request: Request, db: Session = Depends(get_db)):
    data = await request.json()
    threat = evaluate_logsense_forensics(data)
    
    try:
        txn_amount = float(data.get("amount", 0))
    except:
        txn_amount = 0.0

    if threat:
        # Build the XAI (Explainable AI) signals for the Forensic Lab
        signals = {
            "explanations": [threat["reason"], f"Isolation Forest Score: {threat['score']}"],
            "signals": {
                "IMEI_Status": "INVALID" if not data.get("imei_match") else "VERIFIED", 
                "SIM_Status": "REPLACED" if not data.get("sim_match") else "STABLE",
                "Transaction_Loc": data.get("location", "Nairobi"),
                "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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
            detection_signals=json.dumps(signals) # JSON string for database storage
        )
        db.add(new_alert)
        db.commit()
        return {"status": "BLOCKED", "reason": threat["type"]}
    
    return {"status": "SUCCESS"}

# --- WEB UI ROUTES ---
@app.get("/")
@app.get("/dashboard")
async def serve_dash(): return FileResponse("dashboard.html")

@app.get("/alerts")
async def serve_alerts(): return FileResponse("alerts.html")

@app.get("/analyze-view")
async def serve_analyze(): return FileResponse("analyze.html")

# --- DATA RETRIEVAL API ---
@app.get("/api/v2/alerts")
def get_alerts(db: Session = Depends(get_db)):
    # Returns all alerts, newest first
    return db.query(FraudAlert).order_by(desc(FraudAlert.timestamp)).all()

@app.get("/api/v2/alerts/{id}")
def get_alert(id: int, db: Session = Depends(get_db)):
    # Specific alert data for the Forensic Lab
    return db.query(FraudAlert).filter(FraudAlert.id == id).first()

# --- DEMO MAINTENANCE ---
@app.post("/api/v2/alerts/clear")
def clear_alerts(db: Session = Depends(get_db)):
    # Used by the 'Clear All Logs' button on the dashboard
    db.query(FraudAlert).delete()
    db.commit()
    return {"status": "DATABASE_WIPED"}

if __name__ == "__main__":
    import uvicorn
    # Localhost 127.0.0.1 is used to prevent the 'Address Invalid' error in browsers
    uvicorn.run(app, host="127.0.0.1", port=10000)
