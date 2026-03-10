# -*- coding: utf-8 -*-
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc
from datetime import datetime, timedelta
import json
import random
import os
import traceback

# Local imports (Ensure these files exist in your directory)
from database import SessionLocal, engine, get_db, FraudAlert, Base
from fraud_detection_engine import FraudDetectionEngine

# Initialize FastAPI
app = FastAPI(title="LogSense - Kenya Fraud Engine", version="2.5.0")
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
# DATABASE INITIALIZATION & EXPANDED SEEDING
# ============================================
Base.metadata.create_all(bind=engine)

def seed_demo_data():
    """Seeds a variety of Kenyan fraud cases so the dashboard looks active on restart"""
    db = SessionLocal()
    try:
        if db.query(FraudAlert).count() == 0:
            print("🚀 Seeding Expanded Kenyan Demo Data...")
            
            seeds = [
                # 1. RECURRING PATTERN (The "Mary Akinyi" Blacklist)
                FraudAlert(
                    transaction_id="TXN-MPESA-8821", user_id="U1001", user_name="John Kamau",
                    fraud_type="RECURRING_FRAUD_PATTERN", fraud_name="Repeated Fraud Pattern",
                    risk_score=0.99, risk_level="CRITICAL", amount=45000.0,
                    recipient="Mary Akinyi", location="Nairobi", timestamp=datetime.now() - timedelta(hours=2),
                    acknowledged=False, detection_signals=json.dumps({
                        "signals": {"history": "Match found in M-Pesa Blacklist"},
                        "explanations": ["Recipient Mary Akinyi was previously flagged for 'Kamiti' style scams."]
                    })
                ),
                # 2. SIM SWAP (Mombasa Example)
                FraudAlert(
                    transaction_id="TXN-EQUITY-9902", user_id="U2005", user_name="Alice Wambui",
                    fraud_type="SIM_SWAP", fraud_name="SIM Swap Detected",
                    risk_score=0.94, risk_level="CRITICAL", amount=120000.0,
                    recipient="Unknown Agent", location="Mombasa", timestamp=datetime.now() - timedelta(hours=5),
                    acknowledged=False, detection_signals=json.dumps({
                        "signals": {"telco_alert": "SIM replacement 45mins ago", "imei_change": "True"},
                        "explanations": ["High-value transfer immediately following a SIM card replacement."]
                    })
                ),
                # 3. AGENT COLLUSION (Nakuru Example)
                FraudAlert(
                    transaction_id="TXN-BANK-4431", user_id="U3009", user_name="Peter Omondi",
                    fraud_type="AGENT_COLLUSION", fraud_name="Agent Collusion",
                    risk_score=0.82, risk_level="HIGH", amount=15000.0,
                    recipient="Shared Float", location="Nakuru", timestamp=datetime.now() - timedelta(hours=12),
                    acknowledged=True, detection_signals=json.dumps({
                        "signals": {"agent_id": "AG-772", "pattern": "Circular Float Aggregation"},
                        "explanations": ["Transaction involves an agent ID flagged for unusual float movements."]
                    })
                ),
                # 4. SOCIAL ENGINEERING (Urgent Language)
                FraudAlert(
                    transaction_id="TXN-MPESA-1102", user_id="U4002", user_name="Fatuma Ali",
                    fraud_type="SOCIAL_ENGINEERING", fraud_name="Social Engineering",
                    risk_score=0.75, risk_level="HIGH", amount=8500.0,
                    recipient="Health Insurance Claim", location="Garissa", timestamp=datetime.now() - timedelta(days=1),
                    acknowledged=False, detection_signals=json.dumps({
                        "signals": {"note_analysis": "Urgent/Medical Keywords detected"},
                        "explanations": ["User was pressured into a fast transfer using 'Emergency' keywords."]
                    })
                ),
                # 5. IDENTITY THEFT (Odd Hours)
                FraudAlert(
                    transaction_id="TXN-SYS-5567", user_id="U5001", user_name="Kevin Otieno",
                    fraud_type="IDENTITY_THEFT", fraud_name="Identity Theft",
                    risk_score=0.88, risk_level="CRITICAL", amount=65000.0,
                    recipient="Direct Bank Transfer", location="Kisumu", timestamp=datetime.now() - timedelta(hours=22),
                    acknowledged=False, detection_signals=json.dumps({
                        "signals": {"time": "03:15 AM", "velocity": "High"},
                        "explanations": ["Transaction at 3 AM from Kisumu (User usually transacts in Nairobi at noon)."]
                    })
                )
            ]
            db.add_all(seeds)
            db.commit()
            print("✅ Seeding complete. Dashboard is now populated.")
    except Exception as e:
        print(f"❌ Seed error: {e}")
    finally:
        db.close()

seed_demo_data()

# ============================================
# API ENDPOINTS
# ============================================

@app.get("/")
async def root():
    return FileResponse('frontend/login.html')

@app.get("/{page}")
async def serve_frontend(page: str):
    path = f"frontend/{page}.html"
    if os.path.exists(path):
        return FileResponse(path)
    return RedirectResponse(url="/dashboard")

@app.post("/api/mobile/transaction")
async def mobile_transaction(transaction: dict, db: Session = Depends(get_db)):
    """Main endpoint for your Mobile App to send data to"""
    try:
        recipient = transaction.get("recipient", "Unknown")
        amount = float(transaction.get("amount", 0))
        
        # Check if recipient is Mary (The Blacklisted Demo Case)
        prev_flag = db.query(FraudAlert).filter(FraudAlert.recipient == recipient).first()
        
        # Logic for "Mary Akinyi" (Repeated Pattern)
        if recipient == "Mary Akinyi" or prev_flag:
            fraud_type = "RECURRING_FRAUD_PATTERN"
            risk_score = 0.99
            risk_level = "CRITICAL"
            expl = [f"Recipient {recipient} is on the system blacklist.", "Matches historical fraud patterns."]
            signals = {"historical_match": "TRUE", "original_case": "M-Pesa Scam 2025"}
        
        # Logic for Wrong PIN
        elif transaction.get("event") == "WRONG_PIN":
            fraud_type = "WRONG_PIN_ATTEMPT"
            risk_score = 0.85
            risk_level = "HIGH"
            expl = ["Security block: Multiple incorrect PIN entries."]
            signals = {"attempts": 3}
            
        else:
            # Default fallback for random variety
            fraud_type = "IDENTITY_THEFT"
            risk_score = 0.45
            risk_level = "LOW"
            expl = ["Transaction looks normal."]
            signals = {"analysis": "Normal profile"}

        new_alert = FraudAlert(
            transaction_id=f"TXN-{random.randint(1000,9999)}",
            user_id=transaction.get("userId", "U-APP"),
            user_name=transaction.get("userName", "App User"),
            fraud_type=fraud_type,
            fraud_name=fraud_type.replace("_", " ").title(),
            risk_score=risk_score,
            risk_level=risk_level,
            amount=amount,
            recipient=recipient,
            location="Nairobi",
            detection_signals=json.dumps({"signals": signals, "explanations": expl}),
            timestamp=datetime.now()
        )
        db.add(new_alert)
        db.commit()
        
        return {"status": "BLOCKED" if risk_score > 0.7 else "SUCCESS", "alertId": new_alert.id}

    except Exception:
        traceback.print_exc()
        return {"status": "ERROR"}

@app.get("/api/v2/alerts/recent")
def get_recent_alerts(limit: int = 50, db: Session = Depends(get_db)):
    alerts = db.query(FraudAlert).order_by(desc(FraudAlert.timestamp)).limit(limit).all()
    return alerts

@app.get("/api/v2/alerts/{alert_id}")
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(FraudAlert).filter(FraudAlert.id == alert_id).first()
    if not alert: raise HTTPException(status_code=404)
    return alert

@app.post("/api/v2/alerts/{alert_id}/acknowledge")
def acknowledge(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(FraudAlert).filter(FraudAlert.id == alert_id).first()
    if alert:
        alert.acknowledged = True
        db.commit()
    return {"status": "success"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=10000)
