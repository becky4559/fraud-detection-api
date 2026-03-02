from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime
import json
import random
import os

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
# STATIC FILE ROUTES
# ============================================

@app.get("/")
async def read_root():
    return FileResponse('static/index.html')

@app.get("/alerts.html")
async def read_alerts():
    return FileResponse('static/alerts.html')

@app.get("/dashboard.html")
async def read_dashboard():
    return FileResponse('static/dashboard.html')

@app.get("/analyze.html")
async def read_analyze():
    return FileResponse('static/analyze.html')

@app.get("/settings.html")
async def read_settings():
    return FileResponse('static/settings.html')

@app.get("/login.html")
async def read_login():
    return FileResponse('static/login.html')

# ============================================
# EXISTING ENDPOINTS (PRESERVED)
# ============================================

@app.get("/health")
def health():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

@app.get("/fraud-types")
def fraud_types():
    """Return all 8 fraud types with enhanced descriptions"""
    return {
        "total": 8,
        "types": [
            {
                "name": "sim_swap",
                "description": "SIM card swapped and used from new device/location",
                "severity": "CRITICAL",
                "threshold": FRAUD_THRESHOLDS.get("sim_swap", 0.67),
                "enabled": True
            },
            {
                "name": "agent_collusion",
                "description": "Fraudulent collaboration between agents and customers",
                "severity": "HIGH",
                "threshold": FRAUD_THRESHOLDS.get("agent_collusion", 0.73),
                "enabled": True
            },
            {
                "name": "social_engineering",
                "description": "Customer manipulated into authorizing fraudulent transactions",
                "severity": "HIGH",
                "threshold": FRAUD_THRESHOLDS.get("social_engineering", 0.69),
                "enabled": True
            },
            {
                "name": "identity_theft",
                "description": "Stolen personal information used for transactions",
                "severity": "CRITICAL",
                "threshold": FRAUD_THRESHOLDS.get("identity_theft", 0.71),
                "enabled": True
            },
            {
                "name": "mobile_money_fraud",
                "description": "Rapid transactions to multiple recipients from compromised device",
                "severity": "HIGH",
                "threshold": FRAUD_THRESHOLDS.get("mobile_money_fraud", 0.65),
                "enabled": True
            },
            {
                "name": "repayment_fraud",
                "description": "False repayment claims or circular transactions",
                "severity": "MEDIUM",
                "threshold": FRAUD_THRESHOLDS.get("repayment_fraud", 0.62),
                "enabled": True
            },
            {
                "name": "synthetic_identity",
                "description": "Fake identity created from real and fabricated information",
                "severity": "HIGH",
                "threshold": FRAUD_THRESHOLDS.get("synthetic_identity", 0.78),
                "enabled": True
            },
            {
                "name": "device_cloning",
                "description": "Same device ID active in multiple locations simultaneously",
                "severity": "CRITICAL",
                "threshold": FRAUD_THRESHOLDS.get("device_cloning", 0.82),
                "enabled": True
            }
        ]
    }

@app.get("/stats", response_model=StatsResponse)
def get_stats():
    """Get dashboard statistics with monthly data (350+ transactions)"""
    return {
        "total_transactions": 356,
        "high_risk_transactions": 22,
        "fraud_types_configured": 8,
        "users_affected": 18,
        "fraud_amount": 1248500,
        "timestamp": datetime.utcnow().isoformat()
    }

# ============================================
# MOBILE APP ENDPOINT
# ============================================

@app.post("/api/mobile/transaction")
async def mobile_transaction(
    transaction: dict,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    # Extract data from mobile app
    user_id = transaction.get("userId", transaction.get("user_id", "U78901"))
    amount = transaction.get("amount", 0)
    transaction_type = transaction.get("transactionType", transaction.get("type", "transfer"))
    recipient = transaction.get("recipient", "Unknown")
    device_id = transaction.get("deviceId", transaction.get("device_id", f"DEV-{random.randint(1000, 9999)}"))
    location = transaction.get("location", "Nairobi")
    is_end_month = transaction.get("isEndMonth", False)
    
    transaction_id = transaction.get("transactionId", f"TXN-{random.randint(10000, 99999)}")
    
    # Check for WRONG_PIN events
    if transaction.get("event") == "WRONG_PIN":
        alert = FraudAlert(
            transaction_id=transaction_id,
            user_id=user_id,
            fraud_type="wrong_pin_attempt",
            risk_score=0.85,
            reconstruction_error=0.82,
            detection_signals=json.dumps({
                "event": "WRONG_PIN",
                "attempt_number": transaction.get("attempt", 1),
                "device_id": device_id[-4:],
                "location": location,
                "amount": amount
            }),
            email_sent=False
        )
        db.add(alert)
        db.commit()
        
        return {
            "status": "LOGGED",
            "transactionId": transaction_id,
            "riskScore": 0.85,
            "riskLevel": "HIGH",
            "message": f"Wrong PIN attempt {transaction.get('attempt', 1)} recorded"
        }
    
    # Risk calculation
    risk_score = 0.2
    risk_level = "LOW"
    status = "APPROVED"
    
    if amount > 45000:
        risk_score = 0.85
        risk_level = "HIGH"
        status = "PIN_REQUIRED"
    elif amount > 25000:
        if is_end_month:
            risk_score = 0.4
            risk_level = "MEDIUM"
            status = "APPROVED"
        else:
            risk_score = 0.75
            risk_level = "HIGH"
            status = "PIN_REQUIRED"
    
    signals = {
        "amount": f"KES {amount:,.0f}",
        "type": transaction_type,
        "location": location,
        "end_month": is_end_month,
        "recipient": recipient,
        "device_id": device_id[-8:],
        "risk_score": risk_score
    }
    
    reconstruction_error = round(risk_score * 0.85 + 0.12, 2)
    
    # Save to database
    alert = FraudAlert(
        transaction_id=transaction_id,
        user_id=user_id,
        fraud_type="suspicious_transaction" if risk_score >= 0.65 else "normal_transaction",
        risk_score=risk_score,
        reconstruction_error=reconstruction_error,
        detection_signals=json.dumps(signals),
        email_sent=False
    )
    db.add(alert)
    db.commit()
    
    print(f"✅ Alert saved for transaction {transaction_id} (risk: {risk_score})")
    
    return {
        "status": status,
        "transactionId": transaction_id,
        "riskScore": round(risk_score, 2),
        "riskLevel": risk_level,
        "message": f"Transaction {status.lower()}",
        "requiresPin": status == "PIN_REQUIRED"
    }

# ============================================
# OTHER ENDPOINTS (SIM SWAP, IDENTITY THEFT, ETC.)
# ============================================

@app.post("/api/v2/detect/sim-swap")
async def detect_sim_swap_endpoint(request: dict):
    return {"fraud_type": "sim_swap", "risk_score": 0.75, "risk_level": "HIGH"}

@app.post("/api/v2/detect/identity-theft")
async def detect_identity_theft_endpoint(request: dict):
    return {"fraud_type": "identity_theft", "risk_score": 0.82, "risk_level": "CRITICAL"}

@app.post("/api/v2/detect/device-cloning")
async def detect_device_cloning_endpoint(request: dict):
    return {"fraud_type": "device_cloning", "risk_score": 0.68, "risk_level": "HIGH"}

@app.post("/api/v2/detect/mobile-fraud")
async def detect_mobile_fraud_endpoint(request: dict):
    return {"fraud_type": "mobile_money_fraud", "risk_score": 0.71, "risk_level": "HIGH"}

# ============================================
# ALERTS ENDPOINTS
# ============================================

@app.get("/api/v2/alerts/recent")
def get_recent_alerts(limit: int = 10):
    from sqlalchemy import desc
    from database import FraudAlert
    
    db = SessionLocal()
    alerts = db.query(FraudAlert).order_by(desc(FraudAlert.timestamp)).limit(limit).all()
    db.close()
    
    result = []
    for alert in alerts:
        result.append({
            "alert_id": alert.id,
            "transaction_id": alert.transaction_id,
            "user_id": alert.user_id,
            "fraud_type": alert.fraud_type,
            "risk_score": alert.risk_score,
            "risk_level": "HIGH" if alert.risk_score > 0.65 else "MEDIUM" if alert.risk_score > 0.4 else "LOW",
            "detection_signals": json.loads(alert.detection_signals) if alert.detection_signals else {},
            "email_sent": alert.email_sent,
            "timestamp": alert.timestamp.isoformat() if alert.timestamp else None,
            "acknowledged": alert.acknowledged
        })
    
    return result

@app.post("/api/analyze")
async def analyze_transaction(transaction: dict):
    return {"status": "analyzed", "risk_score": 0.45, "risk_level": "MEDIUM"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=10000)
