import os
import json
import random
from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import desc
from fastapi.responses import FileResponse

# Ensure database.py and models are present
from database import SessionLocal, engine, get_db, FraudAlert, Base

app = FastAPI(title="LogSense - Forensic Fraud Engine")

# --- CONFIGURATION ---
os.makedirs("logs", exist_ok=True)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

Base.metadata.create_all(bind=engine)

# --- DEBUG MIDDLEWARE ---
@app.middleware("http")
async def log_requests(request: Request, call_next):
    print(f"DEBUG: Incoming {request.method} request to {request.url.path}")
    response = await call_next(request)
    return response

# --- FORENSIC DATA GENERATORS ---

def generate_forensics(fraud_type, recipient, location):
    now = datetime.now()
    if fraud_type == "SIM_SWAP" or "RECURRING" in fraud_type:
        return {
            "signals": {
                "SIM_Serial_New": f"89254-{random.randint(1000,9999)}-001",
                "Last_Swap_Time": (now - timedelta(minutes=42)).strftime("%H:%M EAT"),
                "Provisioning_Point": f"Agent_{random.randint(100,999)} ({location})",
                "Device_IMEI": f"356781-00-{random.randint(1000,9999)}-09"
            },
            "explanations": [
                "Critical: SIM replacement detected recently.",
                f"Location Anomaly: Transaction initiated from {location}."
            ]
        }
    return {
        "signals": {"Auth_Attempts": 1, "Origin_IP": "192.168.1.45"}, 
        "explanations": ["Manual alert triggered by security engine."]
    }

# --- SEEDING LOGIC ---

def seed_demo_data():
    db = SessionLocal()
    try:
        if db.query(FraudAlert).count() == 0:
            print("STARTING: Seeding LogSense Forensic Demo Data...")
            f1_raw = generate_forensics("RECURRING_FRAUD_PATTERN", "Mary Akinyi", "Nairobi")
            f1_signals = {"explanations": f1_raw["explanations"], "signals": f1_raw["signals"], "reasons": ["RECURRING_FRAUD_PATTERN"]}
            
            db.add(FraudAlert(
                transaction_id="TXN-HIST-8821", 
                user_name="John Kamau",
                fraud_type="RECURRING_FRAUD_PATTERN", 
                fraud_name="Blacklisted Recipient",
                risk_score=0.99, 
                risk_level="CRITICAL", 
                amount=45000.0,
                recipient="Mary Akinyi", 
                location="Nairobi", 
                timestamp=datetime.now() - timedelta(days=1),
                detection_signals=json.dumps(f1_signals), 
                acknowledged=False
            ))
            db.commit()
            print("SUCCESS: Demo data seeded with deep signals.")
    finally:
        db.close()

seed_demo_data()

# --- FRAUD EVALUATION ENGINE ---

def evaluate_fraud(user_name, amount, recipient, location, hour, pin_attempt):
    profiles = {
        "John Kamau": {"limit": 20000, "home": "Nairobi", "hours": range(7, 23)},
        "Alice Wambui": {"limit": 15000, "home": "Mombasa", "hours": range(7, 23)},
    }
    profile = profiles.get(user_name, {"limit": 50000, "home": "Nairobi", "hours": range(7, 23)})
    reasons = []
    risk_score = 0.1 
    
    if "mary" in recipient.lower() or "akinyi" in recipient.lower():
        reasons.append("RECURRING_FRAUD_PATTERN")
        risk_score = 1.0
    if amount > profile["limit"]:
        reasons.append("HIGH_VALUE_ANOMALY")
        risk_score += 0.4
    if location != profile["home"]:
        reasons.append("LOCATION_ANOMALY")
        risk_score += 0.3
    if pin_attempt != "4250":
        reasons.append("SECURITY_VIOLATION")
        risk_score = 1.0

    status = "BLOCKED" if risk_score >= 0.8 else "SUCCESS"
    return status, reasons, min(risk_score, 1.0)

# --- ROUTES ---

@app.get("/")
async def serve_login(): return FileResponse("login.html")

@app.get("/dashboard")
async def serve_dashboard(): return FileResponse("dashboard.html")

@app.get("/analyze")
async def serve_analyze(): return FileResponse("analyze.html")

@app.get("/api/v2/alerts/recent")
def get_recent_alerts(db: Session = Depends(get_db)):
    return db.query(FraudAlert).order_by(desc(FraudAlert.timestamp)).limit(50).all()

@app.get("/api/v2/alerts/{alert_id}")
def get_alert_details(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(FraudAlert).filter(FraudAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert

@app.post("/api/mobile/transaction")
async def mobile_transaction(transaction: dict, db: Session = Depends(get_db)):
    user_name = transaction.get("userName", "Demo User")
    amount = float(transaction.get("amount", 0))
    recipient = transaction.get("recipient", "")
    location = transaction.get("location", "Unknown")
    hour = int(transaction.get("hr", 12)) 
    pin = transaction.get("pin_attempt", "")

    status, flags, score = evaluate_fraud(user_name, amount, recipient, location, hour, pin)

    if status == "BLOCKED":
        f_type = flags[0] if flags else "MULTIPLE_INDICATORS"
        forensics = generate_forensics(f_type, recipient, location)
        
        # KEY FIX: The frontend expects 'explanations' and 'signals'
        combined_signals = {
            "explanations": forensics.get("explanations", []),
            "signals": forensics.get("signals", {}),
            "reasons": flags
        }
        
        new_alert = FraudAlert(
            transaction_id=f"TXN-{random.randint(10000, 99999)}",
            user_name=user_name,
            fraud_type=f_type,
            fraud_name=f_type.replace("_", " ").title(),
            risk_score=score,
            risk_level="CRITICAL",
            amount=amount,
            recipient=recipient,
            location=location,
            timestamp=datetime.now(),
            detection_signals=json.dumps(combined_signals),
            acknowledged=False
        )
        db.add(new_alert)
        db.commit()
        return {"status": "BLOCKED", "message": "Anomaly Detected"}

    return {"status": "SUCCESS", "message": "Authorized"}

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 10000))
    uvicorn.run(app, host="0.0.0.0", port=port)
