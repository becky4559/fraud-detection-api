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
print("Database ready")

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
# FRAUD DETECTION - 8 TYPES WITH EXPLANATIONS
# ============================================

def generate_fraud_alert(user_id, user_name, amount, recipient, location, device_id):
    """Generate a random fraud alert with proper type and explanations"""
    
    # 8 fraud types with their details
    fraud_types = [
        {
            "type": "SIM_SWAP",
            "name": "SIM Swap",
            "risk_score": 0.92,
            "risk_level": "CRITICAL",
            "signals": {
                "new_sim": "SIM card changed 5 minutes before transaction",
                "device_change": "New device detected (IMEI: " + device_id[-8:] + ")",
                "location_change": "Location changed from Nairobi to " + location,
                "impossible_travel": "Cannot travel from Nairobi to " + location + " in 5 minutes"
            },
            "explanation": [
                "New SIM card registered on different device",
                "Transaction from new location (" + location + " vs Nairobi)",
                "Impossible travel time between locations"
            ]
        },
        {
            "type": "IDENTITY_THEFT",
            "name": "Identity Theft",
            "risk_score": 0.88,
            "risk_level": "CRITICAL",
            "signals": {
                "amount_ratio": str(round(amount / 25000, 1)) + "x higher than normal",
                "new_recipient": "First time sending to " + recipient,
                "unusual_time": "Transaction at unusual hour (3:00 AM)"
            },
            "explanation": [
                "Amount is " + str(round(amount / 25000, 1)) + "x higher than normal",
                "Sending to new recipient (first time)",
                "Transaction at unusual hour (3:00 AM)"
            ]
        },
        {
            "type": "DEVICE_CLONING",
            "name": "Device Cloning",
            "risk_score": 0.85,
            "risk_level": "CRITICAL",
            "signals": {
                "multiple_locations": "Same device active in Nairobi and " + location,
                "device_rooted": "Device appears to be rooted/jailbroken"
            },
            "explanation": [
                "Same device active in multiple locations simultaneously",
                "Device appears to be rooted/jailbroken"
            ]
        },
        {
            "type": "MOBILE_MONEY_FRAUD",
            "name": "Mobile Money Fraud",
            "risk_score": 0.78,
            "risk_level": "HIGH",
            "signals": {
                "high_velocity": "5 transactions in last 5 minutes",
                "multiple_recipients": "Sending to 3 different people"
            },
            "explanation": [
                "Multiple rapid transactions detected",
                "Sending to multiple different recipients"
            ]
        },
        {
            "type": "AGENT_COLLUSION",
            "name": "Agent Collusion",
            "risk_score": 0.82,
            "risk_level": "HIGH",
            "signals": {
                "agent_involved": "Transaction involves agent",
                "large_cash_out": "Large cash out amount: KES " + str(amount)
            },
            "explanation": [
                "Transaction involves agent - possible collusion",
                "Large cash out amount"
            ]
        },
        {
            "type": "SOCIAL_ENGINEERING",
            "name": "Social Engineering",
            "risk_score": 0.72,
            "risk_level": "MEDIUM",
            "signals": {
                "new_beneficiary": "Sending to new beneficiary",
                "amount_ratio": str(round(amount / 25000, 1)) + "x higher than normal",
                "urgent_keyword": "Message contains 'urgent'"
            },
            "explanation": [
                "Sending to new beneficiary",
                "Amount " + str(round(amount / 25000, 1)) + "x higher than normal",
                "Urgent language detected"
            ]
        },
        {
            "type": "REPAYMENT_FRAUD",
            "name": "Repayment Fraud",
            "risk_score": 0.68,
            "risk_level": "MEDIUM",
            "signals": {
                "circular_pattern": "Circular transaction pattern detected",
                "amount_mismatch": "Repayment amount doesn't match loan"
            },
            "explanation": [
                "Circular transaction pattern detected",
                "Repayment amount doesn't match loan"
            ]
        },
        {
            "type": "SYNTHETIC_IDENTITY",
            "name": "Synthetic Identity",
            "risk_score": 0.89,
            "risk_level": "CRITICAL",
            "signals": {
                "new_account": "Account created 2 days ago",
                "large_first_tx": "First transaction large amount: KES " + str(amount)
            },
            "explanation": [
                "Account created recently (2 days ago)",
                "First transaction is unusually large"
            ]
        }
    ]
    
    # Randomly select one fraud type for demo
    selected = random.choice(fraud_types)
    
    return selected

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
            print("Alert created: Wrong PIN Attempt for " + user_name)
            
            return {
                "status": "BLOCKED",
                "transactionId": transaction_id,
                "alertId": alert.id,
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
            print("Alert created: Blocked Transaction for " + user_name)
            
            return {"status": "BLOCKED", "message": "Transaction blocked"}
        
        # Generate fraud alert with proper type and explanations
        fraud_data = generate_fraud_alert(user_id, user_name, amount, recipient, location, device_id)
        
        alert = FraudAlert(
            transaction_id=transaction_id,
            user_id=user_id,
            user_name=user_name,
            fraud_type=fraud_data["type"],
            fraud_name=fraud_data["name"],
            risk_score=fraud_data["risk_score"],
            risk_level=fraud_data["risk_level"],
            detection_signals=json.dumps({
                "signals": fraud_data["signals"],
                "explanations": fraud_data["explanation"]
            }),
            amount=amount,
            recipient=recipient,
            location=location,
            timestamp=datetime.now(),
            acknowledged=False
        )
        db.add(alert)
        db.commit()
        print("Alert created: " + fraud_data["name"] + " for " + user_name)
        
        return {
            "status": "SUCCESS",
            "transactionId": transaction_id,
            "alertId": alert.id,
            "message": "Transaction processed"
        }
        
    except Exception as e:
        print("Error in mobile_transaction: " + str(e))
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
        print("Returning " + str(len(result)) + " alerts")
        return result
        
    except Exception as e:
        print("Error in get_recent_alerts: " + str(e))
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
        print("Error in get_alert_details: " + str(e))
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
