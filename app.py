import os
import json
import random
from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import desc
from fastapi.responses import FileResponse, JSONResponse

from database import SessionLocal, engine, get_db, FraudAlert, Base

app = FastAPI(title="LogSense - Forensic Fraud Engine")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

Base.metadata.create_all(bind=engine)

# --- DETAILED DETECTION ENGINE ---
def evaluate_logsense_forensics(data):
    amount = float(data.get("amount", 0))
    recipient = data.get("recipient", "").lower()
    imei_match = data.get("imei_match", True)
    sim_match = data.get("sim_match", True)
    location_score = data.get("location_score", 1.0)
    pin = data.get("pin_attempt", "")

    # 1. DEVICE CLONING
    if not imei_match:
        return {"type": "DEVICE_CLONING", "name": "Mobile Device Cloning Detected", "score": 0.98, "level": "CRITICAL", "reason": "Hardware Fingerprint (IMEI) mismatch."}

    # 2. SIM SWAP
    if not sim_match:
        return {"type": "SIM_SWAP", "name": "Potential SIM Swap Detected", "score": 0.88, "level": "HIGH", "reason": "SIM Serial (ICCID) changed without migration."}

    # 3. IDENTITY THEFT
    if "mary" in recipient or "akinyi" in recipient or location_score < 0.3 or (pin != "" and pin != "4250"):
        return {"type": "IDENTITY_THEFT", "name": "Identity Theft / Account Takeover", "score": 0.95, "level": "CRITICAL", "reason": "Unauthorized access or blacklisted recipient."}

    # 4. MOBILE MONEY FRAUD
    if amount > 30000:
        return {"type": "MOBILE_MONEY_FRAUD", "name": "Mobile Money Fraud Pattern", "score": 0.75, "level": "MEDIUM", "reason": f"High value KES {amount} exceeds baseline."}

    return None

def generate_signals(threat, data):
    return {
        "explanations": [threat["reason"]],
        "signals": {
            "IMEI_Status": "MATCHED" if data.get("imei_match", True) else "CLONED_DETECTED",
            "SIM_Status": "ORIGINAL" if data.get("sim_match", True) else "SWAP_SUSPECTED",
            "Trace_ID": f"LOG-{random.randint(1000,9999)}"
        }
    }

# --- ROUTES ---
@app.post("/api/mobile/transaction")
async def mobile_transaction(request: Request, db: Session = Depends(get_db)):
    try:
        data = await request.json()
        threat = evaluate_logsense_forensics(data)
        
        if threat:
            signals = generate_signals(threat, data)
            new_alert = FraudAlert(
                transaction_id=f"TXN-{random.randint(10000, 99999)}",
                user_name=data.get("userName", "User"),
                fraud_type=threat["type"],
                fraud_name=threat["name"],
                risk_score=threat["score"],
                risk_level=threat["level"],
                amount=float(data.get("amount", 0)),
                recipient=data.get("recipient", "Unknown"),
                location=data.get("location", "Nairobi"),
                timestamp=datetime.now(),
                detection_signals=json.dumps(signals),
                acknowledged=False
            )
            db.add(new_alert)
            db.commit()
            return {"status": "BLOCKED", "reason": threat["type"]}
        
        return {"status": "SUCCESS", "message": "Authorized"}
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})

@app.get("/")
async def serve_login(): return FileResponse("login.html")
@app.get("/dashboard")
async def serve_dashboard(): return FileResponse("dashboard.html")
@app.get("/analyze")
async def serve_analyze(): return FileResponse("analyze.html")
@app.get("/api/v2/alerts/recent")
def get_recent_alerts(db: Session = Depends(get_db)):
    return db.query(FraudAlert).order_by(desc(FraudAlert.timestamp)).limit(50).all()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
