from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
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
# DEBUG ENDPOINT - SEE WHAT FILES EXIST
# ============================================
@app.get("/debug/files")
def debug_files():
    import os
    result = {
        "current_dir": os.getcwd(),
        "files_in_root": os.listdir("."),
        "static_dir_exists": os.path.exists("static"),
    }
    if os.path.exists("static"):
        result["files_in_static"] = os.listdir("static")
    if os.path.exists("frontend"):
        result["files_in_frontend"] = os.listdir("frontend")
    return result

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
# STATIC FILE ROUTES - SERVED DIRECTLY FROM FRONTEND
# ============================================

@app.get("/")
async def read_root():
    if os.path.exists("frontend/index.html"):
        return FileResponse('frontend/index.html')
    return {"message": "LogSense API is running"}

@app.get("/alerts.html")
async def read_alerts():
    if os.path.exists("frontend/alerts.html"):
        return FileResponse('frontend/alerts.html')
    return {"error": "alerts.html not found"}

@app.get("/dashboard.html")
async def read_dashboard():
    if os.path.exists("frontend/dashboard.html"):
        return FileResponse('frontend/dashboard.html')
    return {"error": "dashboard.html not found"}

@app.get("/analyze.html")
async def read_analyze():
    if os.path.exists("frontend/analyze.html"):
        return FileResponse('frontend/analyze.html')
    return {"error": "analyze.html not found"}

@app.get("/settings.html")
async def read_settings():
    if os.path.exists("frontend/settings.html"):
        return FileResponse('frontend/settings.html')
    return {"error": "settings.html not found"}

@app.get("/login.html")
async def read_login():
    if os.path.exists("frontend/login.html"):
        return FileResponse('frontend/login.html')
    return {"error": "login.html not found"}

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
    try:
        from sqlalchemy import desc
        from database import FraudAlert
        
        db = SessionLocal()
        alerts = db.query(FraudAlert).order_by(desc(FraudAlert.timestamp)).limit(limit).all()
        db.close()
        
        result = []
        for alert in alerts:
            # Handle potential None values safely
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
            
            # Calculate risk level
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
        traceback.print_exc()
        return {"error": str(e), "alerts": []}

@app.get("/api/v2/alerts/{alert_id}")
def get_alert_details(alert_id: int):
    try:
        from database import FraudAlert

        db = SessionLocal()
        alert = db.query(FraudAlert).filter(FraudAlert.id == alert_id).first()
        db.close()
        
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        # Handle potential None values safely
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
        
        # Calculate risk level
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
        traceback.print_exc()
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
        print(f"❌ Error in acknowledge_alert: {str(e)}")
        traceback.print_exc()
        return {"success": False, "error": str(e)}

@app.post("/api/analyze")
async def analyze_transaction(transaction: dict):
    return {"status": "analyzed", "risk_score": 0.45, "risk_level": "MEDIUM"}

# ============================================
# EMAIL ALERT ENDPOINTS
# ============================================

@app.get("/api/v2/alerts/email/config")
def get_email_config():
    return {
        "recipient_email": email_service.recipient_email,
        "alerts_enabled": email_service.alerts_enabled,
        "last_updated": datetime.utcnow().isoformat()
    }

@app.post("/api/v2/alerts/email/update")
def update_email_recipient(data: dict):
    new_email = data.get("new_email")
    if new_email:
        email_service.update_recipient(new_email)
        return {"success": True, "recipient": new_email}
    return {"success": False, "error": "No email provided"}

@app.post("/api/v2/alerts/email/toggle")
def toggle_email_alerts(data: dict):
    enabled = data.get("enabled", True)
    email_service.alerts_enabled = enabled
    return {"success": True, "alerts_enabled": enabled}

@app.post("/api/v2/alerts/email/test")
def test_email_alert():
    result = email_service.test_alert()
    return result

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=10000)
