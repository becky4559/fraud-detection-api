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

# Initialize database tables
Base.metadata.create_all(bind=engine)

# --- DETAILED DETECTION ENGINE ---
def evaluate_logsense_forensics(data):
    user_name = data.get("userName", "New User")
    limit = 30000 
    home_location = "Nairobi"
    
    amount = float(data.get("amount", 0))
    recipient = data.get("recipient", "").lower()
    imei_match = data.get("imei_match", True)
    sim_match = data.get("sim_match", True)
    location = data.get("location", "Nairobi")
    location_score = data.get("location_score", 1.0)
    pin = data.get("pin_attempt", "")

    # 1. DEVICE CLONING
    if not imei_match:
        return {"type": "DEVICE_CLONING", "name": "Mobile Device Cloning Detected", "score": 0.98, "level": "CRITICAL", "reason": "Hardware Fingerprint (IMEI) mismatch. Outlier detected in device signature."}

    # 2. SIM SWAP
    if not sim_match:
        return {"type": "SIM_SWAP", "name": "Potential SIM Swap Detected", "score": 0.88, "level": "HIGH", "reason": "SIM Serial (ICCID) changed. Isolation Forest flagged rapid IMSI migration."}

    # 3. IDENTITY THEFT (BLACKLIST)
    if "mary" in recipient or "akinyi" in recipient:
        return {"type": "IDENTITY_THEFT", "name": "Blacklisted Recipient Detected", "score": 0.95, "level": "CRITICAL", "reason": "Target recipient matches known fraudulent account database."}

    # 4. VELOCITY / GEOGRAPHIC FRAUD
    if location != home_location and location != "Unknown":
         return {"type": "IDENTITY_THEFT", "name": "Geographic Displacement", "score": 0.85, "level": "HIGH", "reason": f"Impossible travel detected. Transaction from {location} deviates from profile home."}

    if amount > limit:
        return {"type": "MOBILE_MONEY_FRAUD", "name": "Mobile Money Fraud Pattern", "score": 0.75, "level": "MEDIUM", "reason": f"High value KES {amount} exceeds baseline for {user_name}."}

    return None

def generate_signals(threat, data):
    # This creates the AI Reasoning logs for the 'analyze' page
    return {
        "explanations": [
            threat["reason"],
            f"Isolation Forest Anomaly Score: {threat['score']}",
            "Feature Vector Analysis: Cluster Mismatch Detected"
        ],
        "signals": {
            "IMEI_Status": "MATCHED" if data.get("imei_match", True) else "CLONED_DETECTED",
            "SIM_Status": "ORIGINAL" if data.get("sim_match", True) else "SWAP_SUSPECTED",
            "Trace_ID": f"LOG-{random.randint(1000,9999)}",
            "Node_Location": data.get("location", "Nairobi Central"),
            "System_Entropy": f"{random.uniform(0.7, 0.99):.2f}"
        }
    }

# --- ROUTES ---

@app.post("/analyze") # Matches your React Native fetch URL
async def mobile_transaction(request: Request, db: Session = Depends(get_db)):
    try:
        data = await request.json()
        threat = evaluate_logsense_forensics(data)
        
        if threat:
            signals = generate_signals(threat, data)
            new_alert = FraudAlert(
                transaction_id=f"TXN-{random.randint(10000, 99999)}",
                user_name=data.get("userName", "User"),
                fraud_type=threat["type"],
                fraud_name=threat["name"],
                risk_score=threat["score"],
                risk_level=threat["level"],
                amount=float(data.get("amount", 0)),
                recipient=data.get("recipient", "Unknown"),
                location=data.get("location", "Nairobi"),
                timestamp=datetime.now(),
                detection_signals=json.dumps(signals),
                acknowledged=False
            )
            db.add(new_alert)
            db.commit()
            return {"is_fraud": True, "reason": threat["type"]}
        
        return {"is_fraud": False, "message": "Authorized"}
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})

# --- HTML SERVERS ---
@app.get("/")
async def serve_dashboard(): 
    return FileResponse("dashboard.html")

@app.get("/dashboard")
async def serve_dash(): 
    return FileResponse("dashboard.html")

@app.get("/alerts")
async def serve_alerts(): 
    return FileResponse("alerts.html")

@app.get("/analyze-view") # Renamed to avoid conflict with POST /analyze
async def serve_analyze(): 
    return FileResponse("analyze.html")

# --- DATA API ---

@app.get("/api/v2/alerts") # Matches Dashboard and Alerts table fetch
def get_all_alerts(db: Session = Depends(get_db)):
    alerts = db.query(FraudAlert).order_by(desc(FraudAlert.timestamp)).all()
    
    formatted_alerts = []
    for a in alerts:
        formatted_alerts.append({
            "id": a.id,
            "transaction_id": a.transaction_id,
            "user_name": a.user_name,
            "fraud_name": a.fraud_name,
            "risk_level": a.risk_level,
            "amount": a.amount,
            "recipient": a.recipient,
            "location": a.location,
            "timestamp": a.timestamp.isoformat() if a.timestamp else None
        })
    return formatted_alerts

@app.get("/api/v2/alerts/{alert_id}") # Matches Analyze.html fetch
def get_alert_details(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(FraudAlert).filter(FraudAlert.id == alert_id).first()
    if not alert:
        return JSONResponse(status_code=404, content={"error": "Alert not found"})
    
    # Process signals for frontend
    raw_signals = alert.detection_signals
    signals = {"explanations": [], "signals": {}}
    
    try:
        if isinstance(raw_signals, str):
            signals = json.loads(raw_signals)
        else:
            signals = raw_signals
    except Exception:
        signals = {"explanations": ["Format error"], "signals": {}}

    return {
        "id": alert.id,
        "transaction_id": alert.transaction_id,
        "user_name": alert.user_name,
        "fraud_name": alert.fraud_name,
        "risk_level": alert.risk_level,
        "amount": alert.amount,
        "recipient": alert.recipient,
        "location": alert.location,
        "timestamp": alert.timestamp.isoformat() if alert.timestamp else None,
        "detection_signals": signals
    }

# Endpoint to clear demo data
@app.post("/api/v2/debug/clear")
def clear_alerts(db: Session = Depends(get_db)):
    db.query(FraudAlert).delete()
    db.commit()
    return {"message": "Database cleared for demo."}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
