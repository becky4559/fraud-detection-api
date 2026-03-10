# -*- coding: utf-8 -*-
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc
from datetime import datetime, timedelta
import json
import random
import os
import traceback

# Local imports
from database import SessionLocal, engine, get_db, FraudAlert, Base
from fraud_detection_engine import FraudDetectionEngine

# Initialize FastAPI
app = FastAPI(title="Fraud Detection API - Kenyan Edition", version="2.0.0")

# Initialize fraud detection engine
detection_engine = FraudDetectionEngine()

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================
# DATABASE INITIALIZATION & SEEDING
# ============================================
Base.metadata.create_all(bind=engine)

def seed_demo_data():
    """Seeds historical data so the 'Repeated Pattern' demo works on restart"""
    db = SessionLocal()
    try:
        if db.query(FraudAlert).count() == 0:
            print("Seeding Kenyan Demo Data (Mary Akinyi - Tainted Recipient)...")
            # We create a historical alert for Mary Akinyi
            # This ensures that the NEXT time someone sends to her in the demo, it triggers 'Repeated Pattern'
            demo_alert = FraudAlert(
                transaction_id="TXN-MPESA-INITIAL",
                user_id="U1001",
                user_name="John Kamau",
                fraud_type="MOBILE_MONEY_FRAUD",
                fraud_name="Mobile Money Fraud",
                risk_score=0.92,
                risk_level="CRITICAL",
                amount=15000.0,
                recipient="Mary Akinyi", 
                location="Nakuru",
                timestamp=datetime.now() - timedelta(days=2),
                acknowledged=True,
                detection_signals=json.dumps({
                    "signals": {"note": "Historical fraud entry"},
                    "explanations": ["Previously flagged for suspicious mobile money aggregation"]
                })
            )
            db.add(demo_alert)
            db.commit()
            print("Seeding complete.")
    except Exception as e:
        print(f"Seed error: {e}")
    finally:
        db.close()

seed_demo_data()

# ============================================
# FRONTEND ROUTES
# ============================================

@app.get("/")
async def root():
    return FileResponse('frontend/login.html') if os.path.exists("frontend/login.html") else RedirectResponse(url="/login")

@app.get("/login")
async def login_page():
    return FileResponse('frontend/login.html')

@app.get("/dashboard")
async def dashboard_page():
    return FileResponse('frontend/dashboard.html')

@app.get("/alerts")
async def alerts_page():
    return FileResponse('frontend/alerts.html')

@app.get("/analyze")
async def analyze_page():
    return FileResponse('frontend/analyze.html')

@app.get("/settings")
async def settings_page():
    return FileResponse('frontend/settings.html')

# ============================================
# FRAUD ENGINE HELPERS
# ============================================

FRAUD_TYPES = [
    {"type": "SIM_SWAP", "name": "SIM Swap", "range": (0.85, 0.98), "level": "CRITICAL"},
    {"type": "IDENTITY_THEFT", "name": "Identity Theft", "range": (0.80, 0.95), "level": "CRITICAL"},
    {"type": "DEVICE_CLONING", "name": "Device Cloning", "range": (0.75, 0.90), "level": "CRITICAL"},
    {"type": "AGENT_COLLUSION", "name": "Agent Collusion", "range": (0.70, 0.85), "level": "HIGH"},
    {"type": "SOCIAL_ENGINEERING", "name": "Social Engineering", "range": (0.65, 0.82), "level": "HIGH"}
]

def generate_dynamic_explanations(f_type, amount, location, user_name):
    """Generates Kenyan-specific signals based on type"""
    if f_type == "SIM_SWAP":
        return ["SIM replacement detected via Telco API", "New device IMEI detected", "Impossible travel: Nairobi to " + location], \
               {"telco_alert": "SIM Swap within 24hrs", "location": location}
    
    if f_type == "IDENTITY_THEFT":
        return [f"Transaction for KES {amount} is outside {user_name}'s normal profile", "High-value transfer at midnight"], \
               {"time_check": "Transaction at 3:00 AM", "behavioral_score": "Low"}
               
    return ["Unusual pattern detected", "System flagged high-risk recipient"], {"risk": "Elevated"}

# ============================================
# MAIN MOBILE TRANSACTION ENDPOINT
# ============================================

@app.post("/api/mobile/transaction")
async def mobile_transaction(transaction: dict, db: Session = Depends(get_db)):
    try:
        # 1. Extract Data
        user_name = transaction.get("userName", "John Kamau")
        user_id = transaction.get("userId", "U254")
        amount = float(transaction.get("amount", 0))
        recipient = transaction.get("recipient", "Mary Akinyi")
        location = transaction.get("location", "Nairobi")
        device_id = transaction.get("deviceId", "EQUITY-APP-001")
        
        tx_id = f"KES-{random.randint(100000, 999999)}"
        current_time = datetime.now()
        
        # 2. STATEFUL CHECK: Repeated Pattern (Check if Recipient was ever flagged)
        prev_flag = db.query(FraudAlert).filter(
            FraudAlert.recipient == recipient, 
            FraudAlert.fraud_type != "WRONG_PIN_ATTEMPT"
        ).first()

        # 3. TIMEFRAME CHECK: Odd hours (11 PM - 5 AM)
        is_late_night = current_time.hour < 5 or current_time.hour > 23

        # --- SELECTION LOGIC ---
        risk_score = 0.1
        fraud_type = "NORMAL"
        fraud_name = "Normal Transaction"
        risk_level = "LOW"
        explanations = []
        signals = {"currency": "KES", "device": device_id}

        # Check for Wrong PIN first
        if transaction.get("event") == "WRONG_PIN":
            fraud_type = "WRONG_PIN_ATTEMPT"
            fraud_name = "Wrong PIN Attempt"
            risk_score = 0.88
            risk_level = "HIGH"
            explanations = ["Security block: Incorrect PIN entered for transaction."]
            signals["attempt_number"] = transaction.get("attempt", 1)

        # Check for Repeated Pattern (Blacklisted Recipient)
        elif prev_flag:
            fraud_type = "RECURRING_FRAUD_PATTERN"
            fraud_name = "Repeated Fraud Pattern"
            risk_score = 0.99
            risk_level = "CRITICAL"
            explanations = [
                f"Recipient {recipient} is on the system blacklist.",
                "Previously flagged for fraudulent M-Pesa/Bank activity.",
                "Matches 'Kamiti' social engineering patterns."
            ]
            signals["historical_match"] = "TRUE"
            signals["original_alert_id"] = prev_flag.id

        # Check for Odd Hours
        elif is_late_night:
            fraud_type = "IDENTITY_THEFT"
            fraud_name = "Unusual Transaction Time"
            risk_score = 0.82
            risk_level = "HIGH"
            explanations = [f"Transaction at {current_time.strftime('%H:%M')} is high-risk.", "Deviates from daylight activity profile."]
            signals["time_anomaly"] = "Night-time Activity"

        # Otherwise, pick a random fraud type for demo variety
        else:
            f_obj = random.choice(FRAUD_TYPES)
            fraud_type, fraud_name, risk_level = f_obj["type"], f_obj["name"], f_obj["level"]
            risk_score = random.uniform(f_obj["range"][0], f_obj["range"][1])
            explanations, signals_extra = generate_dynamic_explanations(fraud_type, amount, location, user_name)
            signals.update(signals_extra)

        # 4. Save to Database
        new_alert = FraudAlert(
            transaction_id=tx_id,
            user_id=user_id,
            user_name=user_name,
            fraud_type=fraud_type,
            fraud_name=fraud_name,
            risk_score=round(risk_score, 2),
            risk_level=risk_level,
            detection_signals=json.dumps({"signals": signals, "explanations": explanations}, ensure_ascii=False),
            amount=amount,
            recipient=recipient,
            location=location,
            timestamp=current_time,
            acknowledged=False
        )
        db.add(new_alert)
        db.commit()

        # 5. Return Response to Mobile App
        status = "BLOCKED" if risk_score > 0.7 else "SUCCESS"
        return {
            "status": status,
            "transactionId": tx_id,
            "alertId": new_alert.id,
            "message": "Transaction blocked for security" if status == "BLOCKED" else "Transaction successful"
        }

    except Exception as e:
        print(f"Error: {e}")
        traceback.print_exc()
        return {"status": "ERROR", "message": "Internal Server Error"}

# ============================================
# ALERTS ENDPOINTS
# ============================================

@app.get("/api/v2/alerts/recent")
def get_recent_alerts(limit: int = 50):
    db = SessionLocal()
    try:
        alerts = db.query(FraudAlert).order_by(desc(FraudAlert.timestamp)).limit(limit).all()
        result = []
        for alert in alerts:
            try:
                sig_data = json.loads(alert.detection_signals)
            except:
                sig_data = {"explanations": ["Manual alert entry"]}
                
            result.append({
                "alert_id": alert.id,
                "transaction_id": alert.transaction_id,
                "user_name": alert.user_name,
                "fraud_name": alert.fraud_name,
                "risk_score": alert.risk_score,
                "risk_level": alert.risk_level,
                "amount": alert.amount,
                "recipient": alert.recipient,
                "location": alert.location,
                "timestamp": alert.timestamp.isoformat(),
                "detection_signals": sig_data
            })
        return result
    finally:
        db.close()

@app.get("/api/v2/alerts/{alert_id}")
def get_alert_details(alert_id: int):
    db = SessionLocal()
    try:
        alert = db.query(FraudAlert).filter(FraudAlert.id == alert_id).first()
        if not alert: raise HTTPException(status_code=404, detail="Alert not found")
        return {
            "alert_id": alert.id,
            "transaction_id": alert.transaction_id,
            "user_name": alert.user_name,
            "fraud_name": alert.fraud_name,
            "risk_score": alert.risk_score,
            "risk_level": alert.risk_level,
            "amount": alert.amount,
            "recipient": alert.recipient,
            "location": alert.location,
            "timestamp": alert.timestamp.isoformat(),
            "detection_signals": json.loads(alert.detection_signals)
        }
    finally:
        db.close()

@app.get("/health")
def health():
    return {"status": "healthy", "region": "Kenya", "timestamp": datetime.now().isoformat()}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=10000)
