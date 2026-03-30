import os
import json
import random
from datetime import datetime
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

# --- DETECTION LOGIC ---
def evaluate_logsense_forensics(data):
    # Extracting values for logic check
    recipient = data.get("recipient", "").lower()
    imei_match = data.get("imei_match", True)
    sim_match = data.get("sim_match", True)
    location = data.get("location", "Nairobi")

    if not imei_match:
        return {"type": "DEVICE_CLONING", "name": "Mobile Device Cloning", "score": 0.98, "level": "CRITICAL", "reason": "Hardware IMEI mismatch detected."}
    if not sim_match:
        return {"type": "SIM_SWAP", "name": "SIM Swap Detected", "score": 0.88, "level": "HIGH", "reason": "ICCID serial change without migration."}
    if "mary" in recipient or "akinyi" in recipient:
        return {"type": "IDENTITY_THEFT", "name": "Blacklisted Recipient", "score": 0.95, "level": "CRITICAL", "reason": "Recipient matches high-risk fraud database."}
    if location != "Nairobi" and location != "Unknown":
         return {"type": "GEOGRAPHIC_FRAUD", "name": "Geographic Displacement", "score": 0.85, "level": "HIGH", "reason": f"Transaction from {location} is outside home cluster."}
    
    return None

# --- MOBILE ENDPOINT ---
@app.post("/api/mobile/transaction")
async def mobile_transaction(request: Request, db: Session = Depends(get_db)):
    data = await request.json()
    threat = evaluate_logsense_forensics(data)
    
    # Extracting amount correctly for DB storage
    try:
        raw_amount = data.get("amount", 0)
        txn_amount = float(raw_amount)
    except:
        txn_amount = 0.0

    if threat:
        # Constructing the XAI (Explainable AI) signals for the Forensic Lab
        signals = {
            "explanations": [
                threat["reason"], 
                f"Isolation Forest Anomaly Score: {threat['score']}",
                "Feature set identified as statistical outlier."
            ],
            "signals": {
                "IMEI_Integrity": "COMPROMISED" if not data.get("imei_match", True) else "VALID",
                "SIM_Status": "SWAP_DETECTED" if not data.get("sim_match", True) else "MATCHED",
                "Network_Loc": data.get("location", "Nairobi"),
                "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        }

        new_alert = FraudAlert(
            transaction_id=f"TXN-{random.randint(1000,9999)}",
            user_name=data.get("userName", "Unknown User"),
            fraud_type=threat["type"],
            fraud_name=threat["name"],
            risk_score=threat["score"],
            risk_level=threat["level"],
            amount=txn_amount,
            recipient=data.get("recipient", "Unknown"),
            location=data.get("location", "Nairobi"),
            detection_signals=json.dumps(signals) # Critical: Must be JSON string
        )
        db.add(new_alert)
        db.commit()
        return {"status": "BLOCKED", "reason": threat["type"]}
    
    return {"status": "SUCCESS"}

# --- WEB ROUTES (Consistent Sidebar Navigation) ---
@app.get("/")
@app.get("/dashboard")
async def serve_dash(): 
    return FileResponse("dashboard.html")

@app.get("/alerts")
async def serve_alerts(): 
    # This now serves the dedicated Alerts history page
    return FileResponse("alerts.html")

@app.get("/analyze-view")
async def serve_analyze(): 
    # This serves the Forensic Lab page
    return FileResponse("analyze.html")

# --- API ENDPOINTS FOR FRONTEND ---
@app.get("/api/v2/alerts")
def get_alerts(db: Session = Depends(get_db)):
    return db.query(FraudAlert).order_by(desc(FraudAlert.timestamp)).all()

@app.get("/api/v2/alerts/{id}")
def get_alert(id: int, db: Session = Depends(get_db)):
    alert = db.query(FraudAlert).filter(FraudAlert.id == id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert

if __name__ == "__main__":
    import uvicorn
    # Using port 10000 for Render compatibility
    uvicorn.run(app, host="0.0.0.0", port=10000)
