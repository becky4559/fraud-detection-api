from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from sqlalchemy.orm import Session
from datetime import datetime
import json
import random
import os

from database import SessionLocal, engine, get_db, FraudAlert

app = FastAPI(title="Fraud Detection API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Frontend routes
@app.get("/")
async def root():
    return FileResponse('frontend/login.html')

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

# Mobile transaction endpoint
@app.post("/api/mobile/transaction")
async def mobile_transaction(transaction: dict, db: Session = Depends(get_db)):
    try:
        # Create a test alert
        alert = FraudAlert(
            transaction_id=f"TXN-{random.randint(10000, 99999)}",
            user_id=transaction.get("userId", "U78901"),
            user_name="Test User",
            fraud_type="SIM_SWAP",
            fraud_name="SIM Swap",
            risk_score=0.85,
            risk_level="HIGH",
            detection_signals=json.dumps({"test": True}),
            amount=transaction.get("amount", 0),
            recipient=transaction.get("recipient", "Unknown"),
            location=transaction.get("location", "Nairobi"),
            timestamp=datetime.now(),
            acknowledged=False
        )
        db.add(alert)
        db.commit()
        
        return {"status": "success", "message": "Alert created"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# Alerts endpoint
@app.get("/api/v2/alerts/recent")
def get_recent_alerts(limit: int = 50):
    try:
        from sqlalchemy import desc
        db = SessionLocal()
        alerts = db.query(FraudAlert).order_by(desc(FraudAlert.timestamp)).limit(limit).all()
        db.close()
        
        result = []
        for alert in alerts:
            result.append({
                "alert_id": alert.id,
                "transaction_id": alert.transaction_id,
                "user_id": alert.user_id,
                "user_name": alert.user_name or "Unknown",
                "fraud_type": alert.fraud_type,
                "fraud_name": alert.fraud_name,
                "risk_score": alert.risk_score,
                "risk_level": alert.risk_level,
                "amount": alert.amount,
                "recipient": alert.recipient,
                "location": alert.location,
                "timestamp": alert.timestamp.isoformat() if alert.timestamp else None,
                "acknowledged": alert.acknowledged
            })
        return result
    except Exception as e:
        return {"error": str(e)}

@app.get("/health")
def health():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=10000)
