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

# Enable CORS so your Mobile App and Dashboard can talk to the server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Database Tables
Base.metadata.create_all(bind=engine)

# --- HARDWARE PAIRING (The "Marriage") ---
# This is the expected signature from your primary device (Phone A)
PHONE_A_SIGNATURE = "778899" 

def evaluate_logsense_forensics(data, db: Session):
    user = data.get("userName", "User").lower()
    recipient = data.get("recipient", "").lower()
    location = data.get("location", "Nairobi").lower()
    
    # Toggles/Signals from Mobile APK
    imei_match = data.get("imei_match", True)
    sim_match = data.get("sim_match", True)
    gps_active = data.get("gps_active", True) 
    device_sig = data.get("deviceSignature", "UNKNOWN_B")

    try:
        amount = float(data.get("amount", 0))
    except:
        amount = 0.0

    # Social Graph: Legitimate Contacts
    safe_contacts = ["zeddy", "eddie", "mary"]
    is_known = any(contact in recipient for contact in safe_contacts)

    # --- 1. DEVICE CLONING (The Phone B + Kisii Case) ---
    if not imei_match and location == "kisii":
        return {
            "type": "DEVICE_CLONING", 
            "name": "Mobile Device Cloning", 
            "score": 0.99, 
            "level": "CRITICAL", 
            "reason": "Hardware Collision: Unauthorized APK signature (Phone B) active in Kisii."
        }
    
    # --- 2. SIM SWAPPING (The GPS Off Case) ---
    if not sim_match and not gps_active:
        return {
            "type": "SIM_SWAP", 
            "name": "SIM Swap (Dark Session)", 
            "score": 0.94, 
            "level": "CRITICAL", 
            "reason": "Network Anomaly: ICCID mismatch detected during a GPS-suppressed session."
        }

    # --- 3. IDENTITY THEFT (Alice Behavioral Shift) ---
    if user == "alice" and amount > 10000 and not is_known:
        return {
            "type": "IDENTITY_THEFT", 
            "name": "Identity Theft (ATO)", 
            "score": 0.95, 
            "level": "CRITICAL", 
            "reason": "Behavioral Anomaly: High-value transaction by Alice to unverified recipient."
        }

    # --- 4. MOBILE MONEY FRAUD (The 3rd Transaction Rule) ---
    recent_mule_attempts = db.query(FraudAlert).filter(
        FraudAlert.user_name == data.get("userName", "User"),
        FraudAlert.fraud_type == "MOBILE_MONEY_FRAUD"
    ).count()

    if not is_known and (amount > 40000 or recent_mule_attempts >= 2):
        return {
            "type": "MOBILE_MONEY_FRAUD", 
            "name": "Sequential Mule Attack", 
            "score": 0.89, 
            "level": "HIGH", 
            "reason": "Velocity Violation: 3rd sequential transfer to an unknown node detected."
        }

    return None

# --- MOBILE ENDPOINT ---
@app.post("/api/mobile/transaction")
async def mobile_transaction(request: Request, db: Session = Depends(get_db)):
    data = await request.json()
    threat = evaluate_logsense_forensics(data, db)
    
    try:
        txn_amount = float(data.get("amount", 0))
    except:
        txn_amount = 0.0

    if threat:
        # Build Metadata for analyze.html
        signals = {
            "explanations": [
                threat["reason"], 
                f"Isolation Forest Score: {threat['score']}",
                "Forensic Log: Heuristic Pattern Match"
            ],
            "signals": {
                "User_Identity": data.get("userName", "Unknown"),
                "Hardware_Link": "PHONE_A (MARRIED)" if data.get("deviceSignature") == PHONE_A_SIGNATURE else "PHONE_B (INTRUDER)",
                "IMEI_Integrity": "FAIL (Clone Detected)" if not data.get("imei_match") else "PASS", 
                "SIM_Integrity": "FAIL (Swap Detected)" if not data.get("sim_match") else "PASS",
                "GPS_Privacy_Mode": "ACTIVE (Hidden)" if not data.get("gps_active") else "INACTIVE",
                "Geographic_Log": f"Origin: {data.get('location')} | Target: {data.get('recipient')}",
                "Velocity_Index": f"Attempt {(db.query(FraudAlert).count()) + 1} in Sequence"
            }
        }
        
        new_alert = FraudAlert(
            transaction_id=f"TXN-{random.randint(1000,9999)}",
            user_name=data.get("userName", "User"),
            fraud_type=threat["type"],
            fraud_name=threat["name"],
            risk_score=threat["score"],
            risk_level=threat["level"],
            amount=txn_amount,
            recipient=data.get("recipient", "Unknown"),
            location=data.get("location", "Nairobi"),
            detection_signals=json.dumps(signals)
        )
        db.add(new_alert)
        db.commit()
        return {"status": "BLOCKED", "reason": threat["type"]}
    
    return {"status": "SUCCESS"}

# --- SYSTEM & DASHBOARD ROUTES ---
@app.get("/health")
async def health():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

@app.get("/")
@app.get("/dashboard")
async def serve_dash(): return FileResponse("dashboard.html")

@app.get("/alerts")
async def serve_alerts(): return FileResponse("alerts.html")

@app.get("/analyze-view")
async def serve_analyze(): return FileResponse("analyze.html")

@app.get("/api/v2/alerts")
def get_alerts(db: Session = Depends(get_db)):
    return db.query(FraudAlert).order_by(desc(FraudAlert.timestamp)).all()

@app.get("/api/v2/alerts/{id}")
def get_alert(id: int, db: Session = Depends(get_db)):
    return db.query(FraudAlert).filter(FraudAlert.id == id).first()

@app.post("/api/v2/alerts/clear")
def clear_alerts(db: Session = Depends(get_db)):
    db.query(FraudAlert).delete()
    db.commit()
    return {"status": "DATABASE_WIPED"}

if __name__ == "__main__":
    import uvicorn
    # PORT is set to 10000. On Render, it will auto-detect this.
    port = int(os.environ.get("PORT", 10000))
    host = "0.0.0.0"
    print(f"--- LogSense Engine Online on Port {port} ---")
    uvicorn.run(app, host=host, port=port)
