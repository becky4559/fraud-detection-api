from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime
import json
import random
import os
import traceback

# Local imports
from database import SessionLocal, engine, get_db, Transaction, FraudType, DeviceFingerprint, UserLocation, UserBehavior, FraudAlert, EmailConfig
from models import (
    TransactionResponse, FraudTypeResponse, StatsResponse,
    SimSwapRequest, SimSwapResponse,
    IdentityTheftRequest, IdentityTheftResponse,
    DeviceCloningRequest, DeviceCloningResponse,
    MobileFraudRequest, MobileFraudResponse,
    EmailConfigResponse, EmailTestResponse, FraudAlertResponse, UserBehaviorProfile
)
from fraud_detection_rules import (
    detect_sim_swap, detect_identity_theft, detect_device_cloning,
    detect_mobile_money_fraud, get_risk_level, should_alert, FRAUD_THRESHOLDS
)
from mock_services import MockTelecomAPI, MockBiometricAPI, MockDeviceAPI, MockFraudDatabase
from email_service import email_service

# Initialize FastAPI
app = FastAPI(title="Fraud Detection API", version="2.0.0")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================
# CREATE DATABASE TABLES ON STARTUP
# ============================================
from sqlalchemy import MetaData, Table, Column, Integer, String, Float, Boolean, DateTime

metadata = MetaData()
fraud_alerts = Table(
    'fraud_alerts', metadata,
    Column('id', Integer, primary_key=True),
    Column('transaction_id', String),
    Column('user_id', String),
    Column('fraud_type', String),
    Column('risk_score', Float),
    Column('reconstruction_error', Float),
    Column('detection_signals', String),
    Column('email_sent', Boolean),
    Column('email_recipient', String),
    Column('timestamp', DateTime),
    Column('acknowledged', Boolean)
)
metadata.create_all(engine)
print("✅ fraud_alerts table created/verified")

# ============================================
# FRONTEND ROUTES - Clean URLs
# ============================================

@app.get("/")
async def root():
    if os.path.exists("frontend/login.html"):
        return FileResponse('frontend/login.html')
    return RedirectResponse(url="/login")

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
# EXISTING API ENDPOINTS (PRESERVED)
# ============================================

@app.get("/health")
def health():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

@app.get("/api/v2/alerts/recent")
def get_recent_alerts(limit: int = 10):
    try:
        from sqlalchemy import desc
        from database import FraudAlert
        
        db = SessionLocal()
        alerts = db.query(FraudAlert).order_by(desc(FraudAlert.timestamp)).limit(limit).all()
        db.close()
        
        result = []
        for alert in alerts:
            signals = {}
            if alert.detection_signals:
                try:
                    signals = json.loads(alert.detection_signals)
                except:
                    signals = {"raw": alert.detection_signals}
            
            timestamp = None
            if alert.timestamp:
                try:
                    timestamp = alert.timestamp.isoformat()
                except:
                    timestamp = str(alert.timestamp)
            
            risk_score = alert.risk_score or 0
            if risk_score > 0.65:
                risk_level = "CRITICAL" if risk_score > 0.8 else "HIGH"
            elif risk_score > 0.4:
                risk_level = "MEDIUM"
            else:
                risk_level = "LOW"
            
            result.append({
                "alert_id": alert.id,
                "transaction_id": alert.transaction_id or "N/A",
                "user_id": alert.user_id or "N/A",
                "fraud_type": alert.fraud_type or "unknown",
                "risk_score": risk_score,
                "risk_level": risk_level,
                "detection_signals": signals,
                "email_sent": alert.email_sent or False,
                "timestamp": timestamp,
                "acknowledged": alert.acknowledged or False
            })
        
        return result
    except Exception as e:
        print(f"❌ Error in get_recent_alerts: {str(e)}")
        return []

@app.get("/api/v2/alerts/{alert_id}")
def get_alert_details(alert_id: int):
    try:
        from database import FraudAlert

        db = SessionLocal()
        alert = db.query(FraudAlert).filter(FraudAlert.id == alert_id).first()
        db.close()
        
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        signals = {}
        if alert.detection_signals:
            try:
                signals = json.loads(alert.detection_signals)
            except:
                signals = {"raw": alert.detection_signals}
        
        timestamp = None
        if alert.timestamp:
            try:
                timestamp = alert.timestamp.isoformat()
            except:
                timestamp = str(alert.timestamp)
        
        risk_score = alert.risk_score or 0
        if risk_score > 0.65:
            risk_level = "CRITICAL" if risk_score > 0.8 else "HIGH"
        elif risk_score > 0.4:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return {
            "alert_id": alert.id,
            "transaction_id": alert.transaction_id or "N/A",
            "user_id": alert.user_id or "N/A",
            "fraud_type": alert.fraud_type or "unknown",
            "risk_score": risk_score,
            "risk_level": risk_level,
            "detection_signals": signals,
            "email_sent": alert.email_sent or False,
            "timestamp": timestamp,
            "acknowledged": alert.acknowledged or False
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error in get_alert_details: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v2/alerts/{alert_id}/acknowledge")
def acknowledge_alert(alert_id: int):
    try:
        from database import FraudAlert

        db = SessionLocal()
        alert = db.query(FraudAlert).filter(FraudAlert.id == alert_id).first()
        if alert:
            alert.acknowledged = True
            db.commit()
        db.close()

        return {"success": True, "alert_id": alert_id, "acknowledged": True}
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.post("/api/mobile/transaction")
async def mobile_transaction(
    transaction: dict,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    # Extract data
    user_id = transaction.get("userId", "U78901")
    amount = transaction.get("amount", 0)
    transaction_type = transaction.get("transactionType", "transfer")
    recipient = transaction.get("recipient", "Unknown")
    device_id = transaction.get("deviceId", f"DEV-{random.randint(1000, 9999)}")
    location = transaction.get("location", "Nairobi")
    
    transaction_id = f"TXN-{random.randint(10000, 99999)}"
    
    # Risk calculation
    risk_score = 0.2
    status = "APPROVED"
    
    if amount > 45000:
        risk_score = 0.85
        status = "PIN_REQUIRED"
    
    # Save to database
    alert = FraudAlert(
        transaction_id=transaction_id,
        user_id=user_id,
        fraud_type="suspicious_transaction" if risk_score >= 0.65 else "normal_transaction",
        risk_score=risk_score,
        reconstruction_error=round(risk_score * 0.85, 2),
        detection_signals=json.dumps({
            "amount": amount,
            "type": transaction_type,
            "location": location,
            "recipient": recipient
        }),
        email_sent=False
    )
    db.add(alert)
    db.commit()
    
    print(f"✅ Alert saved: {transaction_id} (risk: {risk_score})")
    
    return {
        "status": status,
        "transactionId": transaction_id,
        "riskScore": risk_score,
        "requiresPin": status == "PIN_REQUIRED"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=10000)
