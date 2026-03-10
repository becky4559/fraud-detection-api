import os
import json
import random
from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from sqlalchemy import desc

# Local imports - Ensure database.py and models are in the same folder
from database import SessionLocal, engine, get_db, FraudAlert, Base

app = FastAPI(title="LogSense - Kenya Fraud Engine")

# 1. CORS CONFIGURATION (Allows your Mobile App and Browser to talk to the API)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 2. DATABASE INITIALIZATION
Base.metadata.create_all(bind=engine)

def seed_demo_data():
    """Seeds the database with historical fraud cases for the demo"""
    db = SessionLocal()
    try:
        if db.query(FraudAlert).count() == 0:
            print("🚀 Seeding Historical Kenyan Fraud Data...")
            
            seeds = [
                # CASE 1: The Historical Blacklist (The 'Past' for your story)
                FraudAlert(
                    transaction_id="TXN-HIST-8821", 
                    user_id="U1001", user_name="John Kamau",
                    fraud_type="RECURRING_FRAUD_PATTERN", 
                    fraud_name="Repeated Fraud Pattern",
                    risk_score=0.99, risk_level="CRITICAL", amount=45000.0,
                    recipient="Mary Akinyi", location="Nairobi", 
                    timestamp=datetime.now() - timedelta(days=1), # Yesterday
                    acknowledged=False, 
                    detection_signals=json.dumps({
                        "signals": {"history": "Blacklisted"},
                        "explanations": ["Recipient 'Mary Akinyi' is a known Fraud Coordinator.", "Linked to previous M-Pesa coordination scams."]
                    })
                ),
                # CASE 2: SIM Swap (Mombasa)
                FraudAlert(
                    transaction_id="TXN-EQUITY-9902", 
                    user_id="U2005", user_name="Alice Wambui",
                    fraud_type="SIM_SWAP", fraud_name="SIM Swap Detected",
                    risk_score=0.94, risk_level="CRITICAL", amount=12000.0,
                    recipient="Unknown Agent", location="Mombasa", 
                    timestamp=datetime.now() - timedelta(hours=5),
                    detection_signals=json.dumps({
                        "signals": {"telco_alert": "SIM replacement 45mins ago"},
                        "explanations": ["High-value transfer immediately following a SIM replacement."]
                    })
                ),
                # CASE 3: Social Engineering
                FraudAlert(
                    transaction_id="TXN-SOC-1102", 
                    user_id="U4002", user_name="Fatuma Ali",
                    fraud_type="SOCIAL_ENGINEERING", fraud_name="Social Engineering",
                    risk_score=0.75, risk_level="HIGH", amount=8500.0,
                    recipient="Emergency Medical Fund", location="Garissa", 
                    timestamp=datetime.now() - timedelta(hours=12),
                    detection_signals=json.dumps({
                        "signals": {"keyword_match": "Urgent/Emergency"},
                        "explanations": ["User pressured into fast transfer via 'Urgent' medical claim keywords."]
                    })
                )
            ]
            db.add_all(seeds)
            db.commit()
            print("✅ Seeding complete.")
    except Exception as e:
        print(f"❌ Seed error: {e}")
    finally:
        db.close()

seed_demo_data()

# 3. STATIC FILE SERVING (Fixes the White Screen on Render)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_PATH = os.path.join(BASE_DIR, "frontend")

if os.path.exists(FRONTEND_PATH):
    app.mount("/static", StaticFiles(directory=FRONTEND_PATH), name="static")

# 4. FRONTEND ROUTES
@app.get("/")
async def serve_login():
    return FileResponse(os.path.join(FRONTEND_PATH, "login.html"))

@app.get("/dashboard")
async def serve_dashboard():
    return FileResponse(os.path.join(FRONTEND_PATH, "dashboard.html"))

@app.get("/alerts")
async def serve_alerts():
    return FileResponse(os.path.join(FRONTEND_PATH, "alerts.html"))

@app.get("/analyze")
async def serve_analyze():
    return FileResponse(os.path.join(FRONTEND_PATH, "analyze.html"))

# 5. API ENDPOINTS
@app.get("/api/v2/alerts/recent")
def get_recent_alerts(db: Session = Depends(get_db)):
    """Used by Dashboard and Alerts page to show data"""
    return db.query(FraudAlert).order_by(desc(FraudAlert.timestamp)).limit(50).all()

@app.get("/api/v2/alerts/{alert_id}")
def get_alert_details(alert_id: int, db: Session = Depends(get_db)):
    """Used by Analyze page"""
    alert = db.query(FraudAlert).filter(FraudAlert.id == alert_id).first()
    if not alert: raise HTTPException(status_code=404)
    return alert

@app.post("/api/mobile/transaction")
async def mobile_transaction(transaction: dict, db: Session = Depends(get_db)):
    """The Live Trigger for your Mobile App"""
    try:
        recipient = transaction.get("recipient", "Unknown")
        amount = float(transaction.get("amount", 0))
        user_name = transaction.get("userName", "App User")
        
        # LOGIC: Check for Mary Akinyi (The Demo Trigger)
        if "mary" in recipient.lower() and "akinyi" in recipient.lower():
            status = "BLOCKED"
            risk_level = "CRITICAL"
            fraud_name = "Repeated Fraud Pattern"
            expl = ["CRITICAL: Recipient is a known Fraud Coordinator.", "Historical match found in LogSense Blacklist."]
            
            # Save the NEW Live Alert to Database
            new_alert = FraudAlert(
                transaction_id=f"TXN-LIVE-{random.randint(1000,9999)}",
                user_id=transaction.get("userId", "U-APP"),
                user_name=user_name,
                fraud_type="RECURRING_FRAUD_PATTERN",
                fraud_name=fraud_name,
                risk_score=0.99,
                risk_level=risk_level,
                amount=amount,
                recipient=recipient,
                location="Nairobi (Mobile)",
                timestamp=datetime.now(),
                detection_signals=json.dumps({"signals": {"live_trigger": "True"}, "explanations": expl})
            )
            db.add(new_alert)
            db.commit()
        else:
            status = "SUCCESS"
            message = "Transaction processed."

        return {
            "status": status,
            "message": "SECURITY ALERT: Transaction Blocked by LogSense" if status == "BLOCKED" else "Success",
            "risk_score": 0.99 if status == "BLOCKED" else 0.01
        }
    except Exception as e:
        return {"status": "ERROR", "message": str(e)}

# 6. SERVER STARTUP
if __name__ == "__main__":
    import uvicorn
    # Render uses the PORT environment variable
    port = int(os.environ.get("PORT", 10000))
    uvicorn.run(app, host="0.0.0.0", port=port)
