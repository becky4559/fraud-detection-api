from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timedelta
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
from fraud_detection_engine import FraudDetectionEngine
from mock_services import MockTelecomAPI, MockBiometricAPI, MockDeviceAPI, MockFraudDatabase
from email_service import email_service

# Initialize FastAPI
app = FastAPI(title="Fraud Detection API", version="2.0.0")

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
    Column('fraud_name', String),  # New field for display name
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
# USER PROFILES STORAGE (In-memory for demo)
# ============================================

user_profiles = {}
user_transactions = {}

def get_user_profile(user_id):
    """Get or create user profile"""
    if user_id not in user_profiles:
        user_profiles[user_id] = {
            'user_id': user_id,
            'avg_amount': 25000,
            'known_locations': ['Nairobi'],
            'known_devices': [],
            'frequent_recipients': [],
            'active_hours': list(range(8, 21)),
            'transaction_count': 0,
            'account_age_days': 0,
            'last_location': None,
            'last_transaction_time': None,
            'recent_failed_pins': 0,
            'recent_transactions': [],
            'transaction_count_5min': 0,
            'unique_recipients_5min': 0,
            'has_credit_history': True
        }
        user_transactions[user_id] = []
    return user_profiles[user_id]

def update_user_profile(user_id, transaction, fraud_result=None):
    """Update user profile with new transaction"""
    profile = get_user_profile(user_id)
    
    # Update transaction count
    profile['transaction_count'] = profile.get('transaction_count', 0) + 1
    
    # Update known locations
    if 'known_locations' not in profile:
        profile['known_locations'] = []
    if transaction.get('location') and transaction['location'] not in profile['known_locations']:
        profile['known_locations'].append(transaction['location'])
    
    # Update known devices
    if 'known_devices' not in profile:
        profile['known_devices'] = []
    if transaction.get('device_id') and transaction['device_id'] not in profile['known_devices']:
        profile['known_devices'].append(transaction['device_id'])
    
    # Update frequent recipients
    if 'frequent_recipients' not in profile:
        profile['frequent_recipients'] = []
    if transaction.get('recipient'):
        profile['frequent_recipients'].append(transaction['recipient'])
        if len(profile['frequent_recipients']) > 20:
            profile['frequent_recipients'] = profile['frequent_recipients'][-20:]
    
    # Update average amount
    amounts = [t['amount'] for t in user_transactions.get(user_id, []) if t.get('amount', 0) > 0]
    amounts.append(transaction['amount'])
    if amounts:
        profile['avg_amount'] = sum(amounts) / len(amounts)
    
    # Update last location and time
    profile['last_location'] = transaction.get('location')
    profile['last_transaction_time'] = transaction.get('timestamp')
    
    # Store transaction
    if user_id not in user_transactions:
        user_transactions[user_id] = []
    user_transactions[user_id].append(transaction)
    
    if len(user_transactions[user_id]) > 100:
        user_transactions[user_id] = user_transactions[user_id][-100:]
    
    # Calculate velocity metrics
    five_min_ago = datetime.now() - timedelta(minutes=5)
    recent_txs = []
    unique_recipients = set()
    
    for tx in user_transactions[user_id]:
        try:
            tx_time = datetime.fromisoformat(tx['timestamp'])
            if tx_time > five_min_ago:
                recent_txs.append(tx)
                if tx.get('recipient'):
                    unique_recipients.add(tx['recipient'])
        except:
            pass
    
    profile['transaction_count_5min'] = len(recent_txs)
    profile['unique_recipients_5min'] = len(unique_recipients)
    
    return profile

# ============================================
# MOBILE APP ENDPOINT - Automatic Fraud Detection
# ============================================

@app.post("/api/mobile/transaction")
async def mobile_transaction(
    transaction: dict,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    try:
        # Extract data from mobile app
        user_id = transaction.get("userId", transaction.get("user_id"))
        if not user_id:
            user_id = "U78901"  # Default for demo
        
        amount = transaction.get("amount", 0)
        transaction_type = transaction.get("transactionType", transaction.get("type", "transfer"))
        recipient = transaction.get("recipient", "Unknown")
        device_id = transaction.get("deviceId", transaction.get("device_id", f"DEV-{random.randint(1000, 9999)}"))
        location = transaction.get("location", "Nairobi")
        timestamp = transaction.get("timestamp", datetime.now().isoformat())
        
        transaction_id = transaction.get("transactionId", f"TXN-{random.randint(10000, 99999)}")
        
        # Check for WRONG_PIN events
        if transaction.get("event") == "WRONG_PIN":
            profile = get_user_profile(user_id)
            profile['recent_failed_pins'] = profile.get('recent_failed_pins', 0) + 1
            
            alert = FraudAlert(
                transaction_id=transaction_id,
                user_id=user_id,
                fraud_type="WRONG_PIN_ATTEMPT",
                fraud_name="Wrong PIN Attempt",
                risk_score=0.85,
                reconstruction_error=0.82,
                detection_signals=json.dumps({
                    "event": "WRONG_PIN",
                    "attempt_number": transaction.get("attempt", 1),
                    "device_id": device_id[-4:],
                    "location": location,
                    "amount": amount
                }),
                email_sent=False,
                timestamp=datetime.now()
            )
            db.add(alert)
            db.commit()
            
            return {
                "status": "BLOCKED",
                "transactionId": transaction_id,
                "riskScore": 0.85,
                "riskLevel": "HIGH",
                "fraudType": "WRONG_PIN_ATTEMPT",
                "fraudName": "Wrong PIN Attempt",
                "message": "Transaction blocked - wrong PIN",
                "requiresPin": False
            }
        
        # Check for BLOCKED transactions (from wrong PIN)
        if transaction.get("event") == "TRANSACTION_BLOCKED":
            alert = FraudAlert(
                transaction_id=transaction_id,
                user_id=user_id,
                fraud_type="BLOCKED_TRANSACTION",
                fraud_name="Blocked Transaction",
                risk_score=0.95,
                reconstruction_error=0.90,
                detection_signals=json.dumps({
                    "reason": transaction.get("reason", "Wrong PIN"),
                    "amount": amount,
                    "location": location
                }),
                email_sent=False,
                timestamp=datetime.now()
            )
            db.add(alert)
            db.commit()
            
            return {"status": "BLOCKED", "message": "Transaction blocked"}
        
        # Get user profile
        profile = get_user_profile(user_id)
        
        # Prepare transaction data for analysis
        tx_data = {
            'user_id': user_id,
            'amount': amount,
            'recipient': recipient,
            'location': location,
            'device_id': device_id,
            'timestamp': timestamp,
            'transaction_type': transaction_type,
            'device_rooted': transaction.get('deviceRooted', False),
            'app_tampered': transaction.get('appTampered', False),
            'note': transaction.get('note', '')
        }
        
        # Run automatic fraud detection
        fraud_result = detection_engine.analyze_transaction(tx_data, profile)
        
        # Determine fraud type (use detected type, default to SUSPICIOUS if none)
        fraud_type = fraud_result['fraud_type']
        fraud_name = fraud_result['fraud_name']
        
        # Update user profile with this transaction
        update_user_profile(user_id, tx_data, fraud_result)
        
        # Save to database with proper fraud type
        alert = FraudAlert(
            transaction_id=transaction_id,
            user_id=user_id,
            fraud_type=fraud_type,
            fraud_name=fraud_name,
            risk_score=fraud_result['risk_score'],
            reconstruction_error=round(fraud_result['risk_score'] * 0.85, 2),
            detection_signals=json.dumps({
                'fraud_name': fraud_name,
                'signals': fraud_result['detection_signals'],
                'all_scores': fraud_result['all_scores'],
                'amount': amount,
                'location': location,
                'recipient': recipient
            }),
            email_sent=False,
            timestamp=datetime.now()
        )
        db.add(alert)
        db.commit()
        
        print(f"✅ Detected: {fraud_name} (score: {fraud_result['risk_score']})")
        
        return {
            "status": "PROCESSED",
            "transactionId": transaction_id,
            "riskScore": fraud_result['risk_score'],
            "riskLevel": fraud_result['risk_level'],
            "fraudType": fraud_type,
            "fraudName": fraud_name,
            "message": f"Transaction analyzed",
            "requiresPin": False
        }
        
    except Exception as e:
        print(f"❌ Error in mobile_transaction: {str(e)}")
        traceback.print_exc()
        return {
            "status": "ERROR",
            "message": "Internal server error",
            "error": str(e)
        }

# ============================================
# USER PROFILE ENDPOINTS (for debugging)
# ============================================

@app.get("/api/user/{user_id}/profile")
def get_user_profile_endpoint(user_id: str):
    profile = get_user_profile(user_id)
    return profile

@app.get("/api/user/{user_id}/transactions")
def get_user_transactions(user_id: str, limit: int = 10):
    txs = user_transactions.get(user_id, [])
    return txs[-limit:]

# ============================================
# ALERTS ENDPOINTS
# ============================================

@app.get("/api/v2/alerts/recent")
def get_recent_alerts(limit: int = 50):
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
            
            # Use fraud_name if available, otherwise format fraud_type
            fraud_name = alert.fraud_name
            if not fraud_name:
                fraud_name = alert.fraud_type.replace('_', ' ').title() if alert.fraud_type else 'Unknown'
            
            result.append({
                "alert_id": alert.id,
                "transaction_id": alert.transaction_id or "N/A",
                "user_id": alert.user_id or "N/A",
                "fraud_type": alert.fraud_type or "UNKNOWN",
                "fraud_name": fraud_name,
                "risk_score": alert.risk_score or 0,
                "risk_level": "CRITICAL" if (alert.risk_score or 0) > 0.7 else "HIGH" if (alert.risk_score or 0) > 0.5 else "MEDIUM" if (alert.risk_score or 0) > 0.3 else "LOW",
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
        
        # Use fraud_name if available
        fraud_name = alert.fraud_name
        if not fraud_name:
            fraud_name = alert.fraud_type.replace('_', ' ').title() if alert.fraud_type else 'Unknown'

        return {
            "alert_id": alert.id,
            "transaction_id": alert.transaction_id or "N/A",
            "user_id": alert.user_id or "N/A",
            "fraud_type": alert.fraud_type or "UNKNOWN",
            "fraud_name": fraud_name,
            "risk_score": alert.risk_score or 0,
            "risk_level": "CRITICAL" if (alert.risk_score or 0) > 0.7 else "HIGH" if (alert.risk_score or 0) > 0.5 else "MEDIUM" if (alert.risk_score or 0) > 0.3 else "LOW",
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

@app.get("/health")
def health():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

@app.get("/stats")
def get_stats():
    return {
        "total_transactions": 356,
        "high_risk_transactions": 22,
        "fraud_types_configured": 8,
        "users_affected": 18,
        "fraud_amount": 1248500,
        "timestamp": datetime.now().isoformat()
    }

# ============================================
# EMAIL ALERT ENDPOINTS
# ============================================

@app.get("/api/v2/alerts/email/config")
def get_email_config():
    return {
        "recipient_email": email_service.recipient_email,
        "alerts_enabled": email_service.alerts_enabled,
        "last_updated": datetime.now().isoformat()
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
