import os
import json
import random
from datetime import datetime, timedelta
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import desc
from database import SessionLocal, engine, get_db, FraudAlert, Base

app = FastAPI(title="LogSense - Forensic Fraud Engine")

# File for Isolation Forest Research
TRANSACTION_LOGS = "logs/transaction_forensics.json"

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def log_event(data, status, flags=[]):
    """Writes raw logs for unsupervised machine learning research."""
    log_entry = {
        **data,
        "server_timestamp": datetime.now().isoformat(),
        "status": status,
        "detection_flags": flags
    }
    with open(TRANSACTION_LOGS, "a") as f:
        f.write(json.dumps(log_entry) + "\n")

def evaluate_fraud(user_name, amount, recipient, location, hour, pin_attempt):
    profiles = {
        "John Kamau": {"limit": 20000, "home": "Nairobi", "hours": range(7, 23)},
        "Alice Wangari": {"limit": 15000, "home": "Mombasa", "hours": range(7, 23)},
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
    if hour not in profile["hours"] or hour < 5 or hour > 23:
        reasons.append("TEMPORAL_OUTLIER")
        risk_score += 0.5
    if location != profile["home"]:
        reasons.append("LOCATION_ANOMALY")
        risk_score += 0.3
    if pin_attempt != "4250":
        reasons.append("SECURITY_VIOLATION")
        risk_score = 1.0

    status = "BLOCKED" if risk_score >= 0.8 else "SUCCESS"
    return status, reasons, min(risk_score, 1.0)

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
        log_event(transaction, "BLOCKED", flags)
        new_alert = FraudAlert(
            transaction_id=f"TXN-{random.randint(10000, 99999)}",
            user_name=user_name,
            fraud_type=flags[0] if flags else "ANOMALY",
            fraud_name=(flags[0] if flags else "Anomaly").replace("_", " ").title(),
            risk_score=score,
            risk_level="CRITICAL",
            amount=amount,
            recipient=recipient,
            location=location,
            detection_signals=json.dumps({"reasons": flags}),
            acknowledged=False
        )
        db.add(new_alert)
        db.commit()
        return {"status": "BLOCKED", "message": "Anomaly Detected", "flags": flags}

    log_event(transaction, "SUCCESS")
    return {"status": "SUCCESS", "message": "Authorized"}

@app.get("/api/v2/alerts/recent")
def get_recent_alerts(db: Session = Depends(get_db)):
    return db.query(FraudAlert).order_by(desc(FraudAlert.timestamp)).limit(50).all()

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 10000))
    uvicorn.run(app, host="0.0.0.0", port=port)
