import os
import json
import random
from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from sqlalchemy import desc

# Ensure database.py and models are present in your directory
from database import SessionLocal, engine, get_db, FraudAlert, Base

app = FastAPI(title="LogSense - Forensic Fraud Engine")

# 1. CORS CONFIGURATION
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 2. DATABASE INITIALIZATION
Base.metadata.create_all(bind=engine)

# --- FORENSIC DATA GENERATOR ---
def generate_forensics(fraud_type, recipient, location):
    """Generates deep technical metadata for the investigation view"""
    now = datetime.now()
    
    if fraud_type == "SIM_SWAP":
        return {
            "signals": {
                "SIM_Serial_New": f"89254-{random.randint(1000,9999)}-001",
                "Last_Swap_Time": (now - timedelta(minutes=42)).strftime("%H:%M EAT"),
                "Provisioning_Point": f"Agent_{random.randint(100,999)} ({location})",
                "Device_IMEI": f"356781-00-{random.randint(1000,9999)}-09",
                "Cell_Tower_ID": "NRB-CBD-V7" if location == "Nairobi" else "MSA-NYALI-P4"
            },
            "explanations": [
                f"Critical: SIM replacement detected {random.randint(30,60)} minutes before transaction.",
                f"Location Anomaly: Transaction initiated from {location} tower while user home profile is Nairobi.",
                "Velocity Trigger: High-value transfer attempted immediately after account recovery."
            ]
        }
    
    elif fraud_type == "RECURRING_FRAUD_PATTERN":
        return {
            "signals": {
                "Blacklist_Source": "LogSense-Global-Database",
                "Historical_Case_ID": f"REF-{random.randint(5000,9999)}",
                "Match_Confidence": "99.8%",
                "Linked_Accounts": random.randint(2, 5),
                "Risk_Category": "Coordination_Scam"
            },
            "explanations": [
                f"Recipient '{recipient}' matches a known fraud coordinator in the blacklist.",
                "Account has been flagged for multiple suspicious incoming transfers this week.",
                "Pattern Match: Social engineering template 'Kamiti-V3' detected."
            ]
        }
    
    return {"signals": {}, "explanations": ["Standard transaction profile."]}

# --- SEEDING LOGIC ---
def seed_demo_data():
    db = SessionLocal()
    try:
        if db.query(FraudAlert).count() == 0:
            print("🚀 Seeding Forensic Demo Data...")
            
            # Case 1: Mary Akinyi (Historical)
            f1 = generate_forensics("RECURRING_FRAUD_PATTERN", "Mary Akinyi", "Nairobi")
            db.add(FraudAlert(
                transaction_id="TXN-HIST-8821", user_name="John Kamau",
                fraud_type="RECURRING_FRAUD_PATTERN", fraud_name="Blacklisted Recipient",
                risk_score=0.99, risk_level="CRITICAL", amount=45000.0,
                recipient="Mary Akinyi", location="Nairobi", 
                timestamp=datetime.now() - timedelta(days=1),
                detection_signals=json.dumps(f1), acknowledged=False
            ))
            
            # Case 2: Alice Wambui (SIM Swap)
            f2 = generate_forensics("SIM_SWAP", "Agent 442", "Mombasa")
            db.add(FraudAlert(
                transaction_id="TXN-EQUITY-9902", user_name="Alice Wambui",
                fraud_type="SIM_SWAP", fraud_name="SIM Swap Detected",
                risk_score=0.94, risk_level="CRITICAL", amount=12500.0,
                recipient="Agent 442", location="Mombasa", 
                timestamp=datetime.now() - timedelta(hours=4),
                detection_signals=json.dumps(f2), acknowledged=False
            ))
            db.commit()
    finally:
        db.close()

seed_demo_data()

# --- STATIC FILES & FRONTEND ROUTES ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_PATH = os.path.join(BASE_DIR, "frontend")

if os.path.exists(FRONTEND_PATH):
    app.mount("/static", StaticFiles(directory=FRONTEND_PATH), name="static")

@app.get("/")
async def serve_login():
    return FileResponse(os.path.join(FRONTEND_PATH, "login.html"))

@app.get("/dashboard")
async def serve_dashboard():
    return FileResponse(os.path.join(FRONTEND_PATH, "dashboard.html"))

@app.get("/alerts")
async def serve_alerts():
    return FileResponse(os.path.join(FRONTEND_PATH, "alerts.html"))

@app.get("/analyze")
async def serve_analyze():
    return FileResponse(os.path.join(FRONTEND_PATH, "analyze.html"))

# --- API ENDPOINTS ---

@app.get("/api/v2/alerts/recent")
def get_recent_alerts(db: Session = Depends(get_db)):
    return db.query(FraudAlert).order_by(desc(FraudAlert.timestamp)).limit(50).all()

@app.get("/api/v2/alerts/{alert_id}")
def get_alert_details(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(FraudAlert).filter(FraudAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert

@app.patch("/api/v2/alerts/{alert_id}/review")
async def review_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(FraudAlert).filter(FraudAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404)
    alert.acknowledged = True
    db.commit()
    return {"status": "SUCCESS"}

@app.post("/api/mobile/transaction")
async def mobile_transaction(transaction: dict, db: Session = Depends(get_db)):
    recipient = transaction.get("recipient", "")
    amount = float(transaction.get("amount", 0))
    user_name = transaction.get("userName", "Demo User")
    
    # TRIGGER LOGIC
    if "mary" in recipient.lower() or amount > 50000:
        f_type = "RECURRING_FRAUD_PATTERN" if "mary" in recipient.lower() else "SIM_SWAP"
        loc = "Mombasa" if amount > 50000 else "Nairobi"
        forensics = generate_forensics(f_type, recipient, loc)
        
        new_alert = FraudAlert(
            transaction_id=f"TXN-LIVE-{random.randint(1000,9999)}",
            user_id=transaction.get("userId", "U-MOBILE"),
            user_name=user_name,
            fraud_type=f_type,
            fraud_name=f_type.replace("_", " ").title(),
            risk_score=0.98,
            risk_level="CRITICAL",
            amount=amount,
            recipient=recipient,
            location=loc,
            timestamp=datetime.now(),
            detection_signals=json.dumps(forensics),
            acknowledged=False
        )
        db.add(new_alert)
        db.commit()
        return {"status": "BLOCKED", "message": "SECURITY ALERT: High Fraud Risk Detected"}
    
    return {"status": "SUCCESS", "message": "Transaction Clear"}

# --- SERVER STARTUP ---
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 10000))
    uvicorn.run(app, host="0.0.0.0", port=port)
