from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from sqlalchemy.orm import Session
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
# DATABASE INITIALIZATION
# ============================================
from database import Base
Base.metadata.create_all(bind=engine)
print("✅ Database ready")

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
    # ... rest of update logic
    return profile

# ============================================
# MOBILE APP ENDPOINT - WITH REAL USER NAMES
# ============================================

@app.post("/api/mobile/transaction")
async def mobile_transaction(
    transaction: dict,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    try:
        # Extract data with real user name
        user_id = transaction.get("userId", "U78901")
        user_name = transaction.get("userName", "Unknown User")
        amount = transaction.get("amount", 0)
        recipient = transaction.get("recipient", "Unknown")
        location = transaction.get("location", "Nairobi")
        device_id = transaction.get("deviceId", f"DEV-{random.randint(1000, 9999)}")
        timestamp = transaction.get("timestamp", datetime.now().isoformat())
        
        transaction_id = f"TXN-{random.randint(10000, 99999)}"
        
        # Handle WRONG_PIN events
        if transaction.get("event") == "WRONG_PIN":
            alert = FraudAlert(
                transaction_id=transaction_id,
                user_id=user_id,
                user_name=user_name,
                fraud_type="WRONG_PIN_ATTEMPT",
                fraud_name="Wrong PIN Attempt",
                risk_score=0.85,
                risk_level="HIGH",
                detection_signals=json.dumps({
                    "event": "WRONG_PIN",
                    "attempt": transaction.get("attempt", 1),
                    "device_id": device_id[-4:],
                    "location": location,
                    "amount": amount
                }),
                amount=amount,
                recipient=recipient,
                location=location,
                timestamp=datetime.now(),
                acknowledged=False
            )
            db.add(alert)
            db.commit()
            print(f"✅ Alert created: Wrong PIN Attempt for {user_name}")
            
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
                user_name=user_name,
                fraud_type="BLOCKED_TRANSACTION",
                fraud_name="Blocked Transaction",
                risk_score=0.95,
                risk_level="CRITICAL",
                detection_signals=json.dumps({
                    "reason": transaction.get("reason", "Wrong PIN"),
                    "amount": amount,
                    "location": location
                }),
                amount=amount,
                recipient=recipient,
                location=location,
                timestamp=datetime.now(),
                acknowledged=False
            )
            db.add(alert)
            db.commit()
            print(f"✅ Alert created: Blocked Transaction for {user_name}")
            
            return {"status": "BLOCKED", "message": "Transaction blocked"}
        
        # Normal transaction - create fraud alert for demo
        # In real app, this would use the detection engine
        fraud_types = ["SIM_SWAP", "IDENTITY_THEFT", "DEVICE_CLONING", "MOBILE_MONEY_FRAUD"]
        fraud_names = ["SIM Swap", "Identity Theft", "Device Cloning", "Mobile Money Fraud"]
        
        # Randomly select a fraud type for demo
        idx = random.randint(0, 3)
        fraud_type = fraud_types[idx]
        fraud_name = fraud_names[idx]
        risk_score = 0.75 + (random.random() * 0.2)
        risk_level = "HIGH" if risk_score > 0.8 else "MEDIUM"
        
        alert = FraudAlert(
            transaction_id=transaction_id,
            user_id=user_id,
            user_name=user_name,
            fraud_type=fraud_type,
            fraud_name=fraud_name,
            risk_score=risk_score,
            risk_level=risk_level,
            detection_signals=json.dumps({
                "amount": amount,
                "recipient": recipient,
                "location": location,
                "time": timestamp
            }),
            amount=amount,
            recipient=recipient,
            location=location,
            timestamp=datetime.now(),
            acknowledged=False
        )
        db.add(alert)
        db.commit()
        print(f"✅ Alert created: {fraud_name} for {user_name}")
        
        return {
            "status": "SUCCESS",
            "transactionId": transaction_id,
            "message": "Transaction processed"
        }
        
    except Exception as e:
        print(f"❌ Error in mobile_transaction: {str(e)}")
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
            
            result.append({
                "alert_id": alert.id,
                "transaction_id": alert.transaction_id,
                "user_id": alert.user_id,
                "user_name": alert.user_name or alert.user_id,
                "fraud_type": alert.fraud_type,
                "fraud_name": alert.fraud_name,
                "risk_score": alert.risk_score or 0,
                "risk_level": alert.risk_level or "MEDIUM",
                "detection_signals": signals,
                "amount": alert.amount or 0,
                "recipient": alert.recipient or "Unknown",
                "location": alert.location or "Unknown",
                "timestamp": alert.timestamp.isoformat() if alert.timestamp else None,
                "acknowledged": alert.acknowledged or False
            })
        
        db.close()
        print(f"��� Returning {len(result)} alerts")
        return result
        
    except Exception as e:
        print(f"❌ Error in get_recent_alerts: {str(e)}")
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

        return {
            "alert_id": alert.id,
            "transaction_id": alert.transaction_id,
            "user_id": alert.user_id,
            "user_name": alert.user_name or alert.user_id,
            "fraud_type": alert.fraud_type,
            "fraud_name": alert.fraud_name,
            "risk_score": alert.risk_score or 0,
            "risk_level": alert.risk_level or "MEDIUM",
            "detection_signals": signals,
            "amount": alert.amount or 0,
            "recipient": alert.recipient or "Unknown",
            "location": alert.location or "Unknown",
            "timestamp": alert.timestamp.isoformat() if alert.timestamp else None,
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
