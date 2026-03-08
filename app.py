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
from database import SessionLocal, engine, get_db, FraudAlert
from fraud_detection_engine import FraudDetectionEngine
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
    Column('user_name', String),
    Column('fraud_type', String),
    Column('fraud_name', String),
    Column('risk_score', Float),
    Column('risk_level', String),
    Column('detection_signals', String),
    Column('amount', Float),
    Column('recipient', String),
    Column('location', String),
    Column('timestamp', DateTime),
    Column('acknowledged', Boolean)
)
metadata.create_all(engine)
print(" fraud_alerts table created/verified")

# ============================================
# FRONTEND ROUTES
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
# USER PROFILES STORAGE
# ============================================

user_profiles = {}
user_transactions = {}
user_flag_count = {}

def get_user_profile(user_id):
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

def update_user_profile(user_id, transaction):
    profile = get_user_profile(user_id)
    profile['transaction_count'] += 1
    
    if transaction.get('location') and transaction['location'] not in profile['known_locations']:
        profile['known_locations'].append(transaction['location'])
    
    if transaction.get('device_id') and transaction['device_id'] not in profile['known_devices']:
        profile['known_devices'].append(transaction['device_id'])
    
    if transaction.get('recipient'):
        profile['frequent_recipients'].append(transaction['recipient'])
        if len(profile['frequent_recipients']) > 20:
            profile['frequent_recipients'] = profile['frequent_recipients'][-20:]
    
    amounts = [t['amount'] for t in user_transactions.get(user_id, []) if t.get('amount', 0) > 0]
    amounts.append(transaction['amount'])
    if amounts:
        profile['avg_amount'] = sum(amounts) / len(amounts)
    
    profile['last_location'] = transaction.get('location')
    profile['last_transaction_time'] = transaction.get('timestamp')
    
    user_transactions[user_id].append(transaction)
    if len(user_transactions[user_id]) > 100:
        user_transactions[user_id] = user_transactions[user_id][-100:]
    
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
# MOBILE APP ENDPOINT
# ============================================

@app.post("/api/mobile/transaction")
async def mobile_transaction(
    transaction: dict,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    try:
        # Extract data
        user_id = transaction.get("userId", "U78901")
        user_name = transaction.get("userName", "Unknown")
        amount = transaction.get("amount", 0)
        recipient = transaction.get("recipient", "Unknown")
        location = transaction.get("location", "Nairobi")
        device_id = transaction.get("deviceId", f"DEV-{random.randint(1000, 9999)}")
        timestamp = transaction.get("timestamp", datetime.now().isoformat())
        
        transaction_id = f"TXN-{random.randint(10000, 99999)}"
        
        # Handle WRONG_PIN events
        if transaction.get("event") == "WRONG_PIN":
            profile = get_user_profile(user_id)
            profile['recent_failed_pins'] += 1
            
            alert = FraudAlert(
                transaction_id=transaction_id,
                user_id=user_id,
                fraud_type="WRONG_PIN_ATTEMPT",
                risk_score=0.85,
                detection_signals=json.dumps({
                    "event": "WRONG_PIN",
                    "attempt": transaction.get("attempt", 1),
                    "device_id": device_id[-4:],
                    "location": location,
                    "amount": amount
                }),
                timestamp=datetime.now(),
                acknowledged=False
            )
            db.add(alert)
            db.commit()
            print(" Alert created: Wrong PIN Attempt for " + user_id)
            
            return {
                "status": "BLOCKED",
                "transactionId": transaction_id,
                "message": "Transaction blocked - wrong PIN"
            }
        
        # Handle BLOCKED transactions
        if transaction.get("event") == "TRANSACTION_BLOCKED":
            alert = FraudAlert(
                transaction_id=transaction_id,
                user_id=user_id,
                fraud_type="BLOCKED_TRANSACTION",
                risk_score=0.95,
                detection_signals=json.dumps({
                    "reason": transaction.get("reason", "Wrong PIN"),
                    "amount": amount,
                    "location": location
                }),
                timestamp=datetime.now(),
                acknowledged=False
            )
            db.add(alert)
            db.commit()
            print(" Alert created: Blocked Transaction for " + user_id)
            
            return {"status": "BLOCKED", "message": "Transaction blocked"}
        
        # Normal transaction - analyze for fraud
        profile = get_user_profile(user_id)
        
        tx_data = {
            'user_id': user_id,
            'amount': amount,
            'recipient': recipient,
            'location': location,
            'device_id': device_id,
            'timestamp': timestamp
        }
        
        # Run fraud detection
        fraud_result = detection_engine.analyze_transaction(tx_data, profile)
        update_user_profile(user_id, tx_data)
        
        # Always save to database if fraud detected
        if fraud_result['fraud_type'] != 'NORMAL':
            alert = FraudAlert(
                transaction_id=transaction_id,
                user_id=user_id,
                fraud_type=fraud_result['fraud_type'],
                risk_score=fraud_result['risk_score'],
                detection_signals=json.dumps({
                    'fraud_name': fraud_result['fraud_name'],
                    'risk_level': fraud_result['risk_level'],
                    'signals': fraud_result['detection_signals'],
                    'all_scores': fraud_result['all_scores'],
                    'amount': amount,
                    'recipient': recipient,
                    'location': location
                }),
                timestamp=datetime.now(),
                acknowledged=False
            )
            db.add(alert)
            db.commit()
            print(" Alert created: " + fraud_result['fraud_name'] + " for " + user_name + " (" + user_id + ")")
            
            # Track flag count for Mary's special rule
            if user_id == 'U78902':
                user_flag_count[user_id] = user_flag_count.get(user_id, 0) + 1
                print(" Mary's flag count: " + str(user_flag_count[user_id]))
        
        return {
            "status": "SUCCESS",
            "transactionId": transaction_id,
            "message": "Transaction processed"
        }
        
    except Exception as e:
        print(" Error in mobile_transaction: " + str(e))
        traceback.print_exc()
        return {"status": "ERROR", "message": str(e)}

# ============================================
# ALERTS ENDPOINTS
# ============================================

@app.get("/api/v2/alerts/recent")
def get_recent_alerts(limit: int = 50):
    try:
        from sqlalchemy import desc
        
        db = SessionLocal()
        alerts = db.query(FraudAlert).order_by(desc(FraudAlert.timestamp)).limit(limit).all()
        
        result = []
        for alert in alerts:
            signals = {}
            if alert.detection_signals:
                try:
                    signals = json.loads(alert.detection_signals)
                except:
                    signals = {"raw": alert.detection_signals}
            
            # Extract fraud_name and risk_level from signals if available
            fraud_name = signals.get('fraud_name', alert.fraud_type.replace('_', ' ').title())
            risk_level = signals.get('risk_level', 'MEDIUM')
            amount = signals.get('amount', 0)
            recipient = signals.get('recipient', 'Unknown')
            location = signals.get('location', 'Unknown')
            
            result.append({
                "alert_id": alert.id,
                "transaction_id": alert.transaction_id,
                "user_id": alert.user_id,
                "user_name": "Unknown",  # We don't store this yet
                "fraud_type": alert.fraud_type,
                "fraud_name": fraud_name,
                "risk_score": alert.risk_score or 0,
                "risk_level": risk_level,
                "detection_signals": signals,
                "amount": amount,
                "recipient": recipient,
                "location": location,
                "timestamp": alert.timestamp.isoformat() if alert.timestamp else None,
                "acknowledged": alert.acknowledged or False
            })
        
        db.close()
        print(" Returning " + str(len(result)) + " alerts")
        return result
        
    except Exception as e:
        print(" Error in get_recent_alerts: " + str(e))
        return []

@app.get("/api/v2/alerts/{alert_id}")
def get_alert_details(alert_id: int):
    try:
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
        
        fraud_name = signals.get('fraud_name', alert.fraud_type.replace('_', ' ').title())
        risk_level = signals.get('risk_level', 'MEDIUM')
        amount = signals.get('amount', 0)
        recipient = signals.get('recipient', 'Unknown')
        location = signals.get('location', 'Unknown')

        return {
            "alert_id": alert.id,
            "transaction_id": alert.transaction_id,
            "user_id": alert.user_id,
            "user_name": "Unknown",
            "fraud_type": alert.fraud_type,
            "fraud_name": fraud_name,
            "risk_score": alert.risk_score or 0,
            "risk_level": risk_level,
            "detection_signals": signals,
            "amount": amount,
            "recipient": recipient,
            "location": location,
            "timestamp": alert.timestamp.isoformat() if alert.timestamp else None,
            "acknowledged": alert.acknowledged or False
        }
    except HTTPException:
        raise
    except Exception as e:
        print(" Error in get_alert_details: " + str(e))
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v2/alerts/{alert_id}/acknowledge")
def acknowledge_alert(alert_id: int):
    try:
        db = SessionLocal()
        alert = db.query(FraudAlert).filter(FraudAlert.id == alert_id).first()
        if alert:
            alert.acknowledged = True
            db.commit()
        db.close()
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}

# ============================================
# HEALTH CHECK
# ============================================

@app.get("/health")
def health():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=10000)
