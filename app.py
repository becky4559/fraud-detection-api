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

# Ensure database.py and models are present
from database import SessionLocal, engine, get_db, FraudAlert, Base

app = FastAPI(title="LogSense Forensic Engine")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

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
                "Device_IMEI": "356781-00-5521-09",
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
                "Blacklist_Source": "CBK-Joint-Taskforce",
                "Historical_ID": f"REF-{random.randint(5000,9999)}",
                "Match_Confidence": "99.8%",
                "Linked_Accounts": 3,
                "Risk_Category": "Coordination_Scam"
            },
            "explanations": [
                f"Recipient '{recipient}' matches a known fraud coordinator in the M-Pesa Blacklist.",
                "Account has been flagged for 3 suspicious incoming 'medical emergency' transfers this week.",
                "Pattern Match: Social engineering template 'Kamiti-V3' detected in SMS meta-data."
            ]
        }
    
    return {"signals": {}, "explanations": ["Standard transaction profile."]}

# --- SEEDING ---
def seed_demo():
    db = SessionLocal()
    try:
        if db.query(FraudAlert).count() == 0:
            # Seed Mary Akinyi (Historical)
            f1 = generate_forensics("RECURRING_FRAUD_PATTERN", "Mary Akinyi", "Nairobi")
            db.add(FraudAlert(
                transaction_id="TXN-HIST-001", user_name="John Kamau",
                fraud_type="RECURRING_FRAUD_PATTERN", fraud_name="Blacklisted Recipient",
                risk_score=0.99, risk_level="CRITICAL", amount=45000.0,
                recipient="Mary Akinyi", location="Nairobi", timestamp=datetime.now()-timedelta(days=1),
                detection_signals=json.dumps(f1)
            ))
            # Seed Alice Wambui (SIM Swap)
            f2 = generate_forensics("SIM_SWAP", "Agent 442", "Mombasa")
            db.add(FraudAlert(
                transaction_id="TXN-HIST-002", user_name="Alice Wambui",
                fraud_type="SIM_SWAP", fraud_name="SIM Swap Detected",
                risk_score=0.94, risk_level="CRITICAL", amount=12500.0,
                recipient="Agent 442", location="Mombasa", timestamp=datetime.now()-timedelta(hours=4),
                detection_signals=json.dumps(f2)
            ))
            db.commit()
    finally: db.close()

seed_demo()

# --- ROUTES ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND = os.path.join(BASE_DIR, "frontend")

if os.path.exists(FRONTEND):
    app.mount("/static", StaticFiles(directory=FRONTEND), name="static")

@app.get("/")
async def login(): return FileResponse(os.path.join(FRONTEND, "login.html"))

@app.get("/dashboard")
async def dash(): return FileResponse(os.path.join(FRONTEND, "dashboard.html"))

@app.get("/alerts")
async def alrt(): return FileResponse(os.path.join(FRONTEND, "alerts.html"))

@app.get("/analyze")
async def anlyz(): return FileResponse(os.path.join(FRONTEND, "analyze.html"))

# --- API ---
@app.get("/api/v2/alerts/recent")
def get_alerts(db: Session = Depends(get_db)):
    return db.query(FraudAlert).order_by(desc(FraudAlert.timestamp)).limit(50).all()

@app.get("/api/v2/alerts/{alert_id}")
def get_details(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(FraudAlert).filter(FraudAlert.id == alert_id).first()
    if not alert: raise HTTPException(status_code=404)
    return alert

@app.post("/api/mobile/transaction")
async def mobile_txn(transaction: dict, db: Session = Depends(get_db)):
    recp = transaction.get("recipient", "")
    amt = float(transaction.get("amount", 0))
    
    if "mary" in recp.lower() or amt > 50000:
        f_type = "RECURRING_FRAUD_PATTERN" if "mary" in recp.lower() else "SIM_SWAP"
        loc = "Mombasa" if amt > 50000 else "Nairobi"
        forensics = generate_forensics(f_type, recp, loc)
        
        new_alert = FraudAlert(
            transaction_id=f"TXN-LIVE-{random.randint(1000,9999)}",
            user_id="U-MOBILE", user_name=transaction.get("userName", "Demo User"),
            fraud_type=f_type, fraud_name=f_type.replace("_", " "),
            risk_score=0.98, risk_level="CRITICAL", amount=amt,
            recipient=recp, location=loc, timestamp=datetime.now(),
            detection_signals=json.dumps(forensics)
        )
        db.add(new_alert); db.commit()
        return {"status": "BLOCKED", "message": "LogSense: High Fraud Risk Detected"}
    
    return {"status": "SUCCESS", "message": "Clear"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
