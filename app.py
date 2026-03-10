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

# Local imports
from database import SessionLocal, engine, get_db, FraudAlert, Base

app = FastAPI(title="LogSense API")

# 1. FIX CORS: Allow all for the demo to prevent browser blocks
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 2. DATABASE SETUP
Base.metadata.create_all(bind=engine)

def seed_demo_data():
    db = SessionLocal()
    try:
        if db.query(FraudAlert).count() == 0:
            seeds = [
                FraudAlert(
                    transaction_id=f"TXN-{random.randint(1000,9999)}", user_id="U101", user_name="John Kamau",
                    fraud_type="RECURRING_FRAUD_PATTERN", fraud_name="Repeated Fraud Pattern",
                    risk_score=0.98, risk_level="CRITICAL", amount=45000.0,
                    recipient="Mary Akinyi", location="Nairobi", timestamp=datetime.now(),
                    detection_signals=json.dumps({"signals": {"history": "Blacklisted"}, "explanations": ["Linked to Kamiti Scam"]})
                ),
                FraudAlert(
                    transaction_id=f"TXN-{random.randint(1000,9999)}", user_id="U205", user_name="Alice Wambui",
                    fraud_type="SIM_SWAP", fraud_name="SIM Swap Detected",
                    risk_score=0.92, risk_level="CRITICAL", amount=12000.0,
                    recipient="Agent 442", location="Mombasa", timestamp=datetime.now() - timedelta(hours=3),
                    detection_signals=json.dumps({"signals": {"sim_age": "2hrs"}, "explanations": ["Recent SIM replacement"]})
                )
            ]
            db.add_all(seeds)
            db.commit()
    finally:
        db.close()

seed_demo_data()

# 3. STATIC FILES (CRITICAL: Fixes the white screen)
# This mounts the "frontend" folder so Render can serve CSS/JS
if os.path.exists("frontend"):
    app.mount("/static", StaticFiles(directory="frontend"), name="static")

# 4. FRONTEND ROUTES (Absolute Pathing)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

@app.get("/")
async def serve_login():
    return FileResponse(os.path.join(BASE_DIR, "frontend", "login.html"))

@app.get("/dashboard")
async def serve_dashboard():
    return FileResponse(os.path.join(BASE_DIR, "frontend", "dashboard.html"))

@app.get("/alerts")
async def serve_alerts():
    return FileResponse(os.path.join(BASE_DIR, "frontend", "alerts.html"))

# 5. API ENDPOINTS
@app.get("/api/v2/alerts/recent")
def get_alerts(db: Session = Depends(get_db)):
    return db.query(FraudAlert).order_by(desc(FraudAlert.timestamp)).limit(50).all()

@app.post("/api/mobile/transaction")
async def mobile_txn(transaction: dict, db: Session = Depends(get_db)):
    # Your transaction logic here...
    return {"status": "SUCCESS"}

if __name__ == "__main__":
    import uvicorn
    # Use the port Render expects
    port = int(os.environ.get("PORT", 10000))
    uvicorn.run(app, host="0.0.0.0", port=port)
