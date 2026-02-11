from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Optional
from datetime import datetime
import json
import random

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
from mock_services import MockTelecomAPI, MockBiometricAPI, MockDeviceAPI, MockFraudDatabase
from email_service import email_service

# Initialize FastAPI
app = FastAPI(title="Fraud Detection API", version="2.0.0")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For demo - restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================
# EXISTING ENDPOINTS (PRESERVED)
# ============================================

@app.get("/")
def root():
    return {
        "api": "African Fraud Detection System",
        "version": "2.0.0",
        "status": "active",
        "features": [
            "SIM Swap Detection",
            "Identity Theft Detection",
            "Device Cloning Detection",
            "Mobile Money Fraud Detection",
            "Email Alerts"
        ],
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/health")
def health():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

@app.get("/fraud-types")
def fraud_types():
    """Return all 8 fraud types with enhanced descriptions"""
    return {
        "total": 8,
        "types": [
            {
                "name": "sim_swap",
                "description": "SIM card swapped and used from new device/location",
                "severity": "CRITICAL",
                "threshold": FRAUD_THRESHOLDS.get("sim_swap", 0.67),
                "enabled": True
            },
            {
                "name": "agent_collusion",
                "description": "Fraudulent collaboration between agents and customers",
                "severity": "HIGH",
                "threshold": FRAUD_THRESHOLDS.get("agent_collusion", 0.73),
                "enabled": True
            },
            {
                "name": "social_engineering",
                "description": "Customer manipulated into authorizing fraudulent transactions",
                "severity": "HIGH",
                "threshold": FRAUD_THRESHOLDS.get("social_engineering", 0.69),
                "enabled": True
            },
            {
                "name": "identity_theft",
                "description": "Stolen personal information used for transactions",
                "severity": "CRITICAL",
                "threshold": FRAUD_THRESHOLDS.get("identity_theft", 0.71),
                "enabled": True
            },
            {
                "name": "mobile_money_fraud",
                "description": "Rapid transactions to multiple recipients from compromised device",
                "severity": "HIGH",
                "threshold": FRAUD_THRESHOLDS.get("mobile_money_fraud", 0.65),
                "enabled": True
            },
            {
                "name": "repayment_fraud",
                "description": "False repayment claims or circular transactions",
                "severity": "MEDIUM",
                "threshold": FRAUD_THRESHOLDS.get("repayment_fraud", 0.62),
                "enabled": True
            },
            {
                "name": "synthetic_identity",
                "description": "Fake identity created from real and fabricated information",
                "severity": "HIGH",
                "threshold": FRAUD_THRESHOLDS.get("synthetic_identity", 0.78),
                "enabled": True
            },
            {
                "name": "device_cloning",
                "description": "Same device ID active in multiple locations simultaneously",
                "severity": "CRITICAL",
                "threshold": FRAUD_THRESHOLDS.get("device_cloning", 0.82),
                "enabled": True
            }
        ]
    }

@app.get("/stats", response_model=StatsResponse)
def get_stats():
    """Get dashboard statistics with monthly data (350+ transactions)"""
    # Simulate monthly stats (Feb 2026)
    return {
        "total_transactions": 356,  # Monthly total
        "high_risk_transactions": 22,  # ~6.2% fraud rate
        "fraud_types_configured": 8,
        "users_affected": 18,
        "fraud_amount": 1248500,  # KES 1.25M saved
        "timestamp": datetime.utcnow().isoformat()
    }

# ============================================
# NEW FRAUD DETECTION ENDPOINTS
# ============================================

@app.post("/api/v2/detect/sim-swap", response_model=SimSwapResponse)
async def detect_sim_swap_endpoint(
    request: SimSwapRequest,
    background_tasks: BackgroundTasks
):
    """
    Detect SIM swap fraud using:
    - Device fingerprint changes
    - Location anomalies
    - Failed PIN attempts
    - Telecom provider data (mock)
    """
    
    # Get mock telecom data
    if request.phone_number:
        sim_status = MockTelecomAPI.check_sim_status(request.phone_number)
        pin_attempts = MockTelecomAPI.check_failed_pin_attempts(request.phone_number)
    else:
        sim_status = {"sim_changed": False}
        pin_attempts = {"failed_attempts_24h": request.failed_pin_attempts}
    
    # Get device intelligence
    device_data = MockDeviceAPI.check_device(request.device_id, request.ip_address)
    
    # Calculate risk score using autoencoder-derived rules
    risk_score, signals = detect_sim_swap(
        device_is_new=device_data.get("trust_score", 0.5) < 0.4,
        location_changed=sim_status.get("sim_changed", False),
        time_since_last_auth=random.randint(0, 48),  # Simulate
        failed_pin_count=pin_attempts.get("failed_attempts_24h", request.failed_pin_attempts),
        carrier_changed=sim_status.get("sim_changed", False)
    )
    
    # Add mock service signals
    signals["sim_swapped"] = sim_status.get("sim_changed", False)
    signals["carrier"] = sim_status.get("new_carrier", sim_status.get("carrier", "Unknown"))
    signals["device_trust_score"] = round(device_data.get("trust_score", 0.5), 2)
    
    risk_level = get_risk_level(risk_score)
    alert_needed = should_alert(risk_score, "sim_swap")
    
    # Send email alert if needed
    if alert_needed:
        alert_data = {
            "transaction_id": request.transaction_id or f"TXN-{random.randint(10000, 99999)}",
            "user_id": request.user_id,
            "fraud_type": "sim_swap",
            "risk_score": risk_score,
            "risk_level": risk_level,
            "amount": random.randint(5000, 50000),  # Simulate
            "reconstruction_error": round(risk_score * 0.85 + 0.15, 2),
            "detection_signals": signals,
            "timestamp": datetime.utcnow().isoformat()
        }
        background_tasks.add_task(email_service.send_alert, alert_data)
    
    return SimSwapResponse(
        fraud_type="sim_swap",
        risk_score=round(risk_score, 2),
        risk_level=risk_level,
        alert_required=alert_needed,
        detection_signals=signals,
        reconstruction_error=round(risk_score * 0.85 + 0.15, 2),
        timestamp=datetime.utcnow().isoformat()
    )

@app.post("/api/v2/detect/identity-theft", response_model=IdentityTheftResponse)
async def detect_identity_theft_endpoint(
    request: IdentityTheftRequest,
    background_tasks: BackgroundTasks
):
    """Detect identity theft fraud"""
    
    # Get mock biometric verification
    biometric = MockBiometricAPI.verify_identity(request.user_id)
    
    # Get device intelligence
    device_data = MockDeviceAPI.check_device(request.device_id)
    
    # Calculate risk score
    risk_score, signals = detect_identity_theft(
        amount_ratio=request.amount / (request.avg_transaction_amount or 2500),
        device_is_new=device_data.get("trust_score", 0.5) < 0.4,
        location_changed=random.choice([True, False]),  # Simulate
        behavior_score=request.behavior_score or 0.5,
        document_verified=biometric.get("verified", False)
    )
    
    # Add mock service signals
    signals["biometric_match"] = biometric.get("match_score", 0)
    signals["verification_status"] = "VERIFIED" if biometric.get("verified") else "FAILED"
    signals["amount"] = f"KES {request.amount:,.0f}"
    
    risk_level = get_risk_level(risk_score)
    alert_needed = should_alert(risk_score, "identity_theft")
    
    if alert_needed:
        alert_data = {
            "transaction_id": request.transaction_id or f"TXN-{random.randint(10000, 99999)}",
            "user_id": request.user_id,
            "fraud_type": "identity_theft",
            "risk_score": risk_score,
            "risk_level": risk_level,
            "amount": request.amount,
            "reconstruction_error": round(risk_score * 0.88 + 0.12, 2),
            "detection_signals": signals,
            "timestamp": datetime.utcnow().isoformat()
        }
        background_tasks.add_task(email_service.send_alert, alert_data)
    
    return IdentityTheftResponse(
        fraud_type="identity_theft",
        risk_score=round(risk_score, 2),
        risk_level=risk_level,
        alert_required=alert_needed,
        detection_signals=signals,
        reconstruction_error=round(risk_score * 0.88 + 0.12, 2),
        timestamp=datetime.utcnow().isoformat()
    )

@app.post("/api/v2/detect/device-cloning", response_model=DeviceCloningResponse)
async def detect_device_cloning_endpoint(
    request: DeviceCloningRequest,
    background_tasks: BackgroundTasks
):
    """Detect device cloning fraud"""
    
    # Get device intelligence
    device_data = MockDeviceAPI.check_device(request.device_id, request.ip_address)
    
    # Calculate risk score
    risk_score, signals = detect_device_cloning(
        device_id=request.device_id,
        active_locations=device_data.get("active_locations", []),
        device_rooted=device_data.get("rooted", False),
        app_tampered=device_data.get("app_tampered", False)
    )
    
    # Add location details
    locations = []
    for loc in device_data.get("active_locations", [])[:3]:
        locations.append(f"{loc.get('city', 'Unknown')}, {loc.get('country', 'Unknown')}")
    
    signals["active_location_count"] = device_data.get("location_count", 0)
    signals["locations"] = locations
    signals["device_risk"] = device_data.get("risk_level", "UNKNOWN")
    
    risk_level = get_risk_level(risk_score)
    alert_needed = should_alert(risk_score, "device_cloning")
    
    if alert_needed:
        alert_data = {
            "transaction_id": request.transaction_id or f"TXN-{random.randint(10000, 99999)}",
            "user_id": request.user_id,
            "fraud_type": "device_cloning",
            "risk_score": risk_score,
            "risk_level": risk_level,
            "amount": random.randint(10000, 100000),
            "reconstruction_error": round(risk_score * 0.92 + 0.08, 2),
            "detection_signals": signals,
            "timestamp": datetime.utcnow().isoformat()
        }
        background_tasks.add_task(email_service.send_alert, alert_data)
    
    return DeviceCloningResponse(
        fraud_type="device_cloning",
        risk_score=round(risk_score, 2),
        risk_level=risk_level,
        alert_required=alert_needed,
        detection_signals=signals,
        active_locations=locations,
        device_rooted=device_data.get("rooted", False),
        app_tampered=device_data.get("app_tampered", False),
        timestamp=datetime.utcnow().isoformat()
    )

@app.post("/api/v2/detect/mobile-fraud", response_model=MobileFraudResponse)
async def detect_mobile_fraud_endpoint(
    request: MobileFraudRequest,
    background_tasks: BackgroundTasks
):
    """Detect mobile money fraud (rapid transactions, multiple recipients)"""
    
    # Get fraud database check
    fraud_db_check = MockFraudDatabase.check_phone_risk(f"2547{random.randint(100000, 999999)}")
    
    # Calculate risk score
    risk_score, signals = detect_mobile_money_fraud(
        transaction_count_5min=request.transaction_count_5min,
        unique_recipients=request.recipient_count,
        avg_amount=request.avg_transaction_amount or 2500,
        current_amount=request.amount,
        device_trust_score=request.device_trust_score
    )
    
    # Add fraud database signals
    signals["recipient_risk_score"] = round(fraud_db_check.get("risk_score", 0.3), 2)
    signals["transaction_velocity"] = f"{request.transaction_count_5min} in 5min"
    signals["unique_recipients"] = request.recipient_count
    
    risk_level = get_risk_level(risk_score)
    alert_needed = should_alert(risk_score, "mobile_money_fraud")
    
    if alert_needed:
        alert_data = {
            "transaction_id": request.transaction_id or f"TXN-{random.randint(10000, 99999)}",
            "user_id": request.user_id,
            "fraud_type": "mobile_money_fraud",
            "risk_score": risk_score,
            "risk_level": risk_level,
            "amount": request.amount,
            "reconstruction_error": round(risk_score * 0.82 + 0.18, 2),
            "detection_signals": signals,
            "timestamp": datetime.utcnow().isoformat()
        }
        background_tasks.add_task(email_service.send_alert, alert_data)
    
    return MobileFraudResponse(
        fraud_type="mobile_money_fraud",
        risk_score=round(risk_score, 2),
        risk_level=risk_level,
        alert_required=alert_needed,
        detection_signals=signals,
        velocity_5min=request.transaction_count_5min,
        unique_recipients=request.recipient_count,
        reconstruction_error=round(risk_score * 0.82 + 0.18, 2),
        timestamp=datetime.utcnow().isoformat()
    )

# ============================================
# EMAIL ALERT ENDPOINTS
# ============================================

@app.get("/api/v2/alerts/email/config", response_model=EmailConfigResponse)
def get_email_config():
    """Get current email alert configuration"""
    return EmailConfigResponse(
        recipient_email=email_service.recipient_email,
        alerts_enabled=email_service.alerts_enabled,
        last_updated=datetime.utcnow().isoformat()
    )

@app.post("/api/v2/alerts/email/update")
def update_email_recipient(new_email: str):
    """Update email alert recipient"""
    result = email_service.update_recipient(new_email)
    return result

@app.post("/api/v2/alerts/email/test", response_model=EmailTestResponse)
def test_email_alert():
    """Send a test alert email"""
    result = email_service.test_alert()
    return EmailTestResponse(
        success=result["success"],
        recipient=result["recipient"],
        sent_at=result["sent_at"],
        message=result["message"]
    )

@app.post("/api/v2/alerts/email/toggle")
def toggle_email_alerts(enabled: bool):
    """Enable or disable email alerts"""
    email_service.alerts_enabled = enabled
    return {
        "success": True,
        "alerts_enabled": enabled,
        "timestamp": datetime.utcnow().isoformat()
    }

# ============================================
# ALERTS HISTORY ENDPOINTS
# ============================================

@app.get("/api/v2/alerts/recent", response_model=List[FraudAlertResponse])
def get_recent_alerts(limit: int = 10):
    """Get recent fraud alerts"""
    # Return mock alerts for demo
    alerts = []
    fraud_types = ["sim_swap", "identity_theft", "device_cloning", "mobile_money_fraud"]
    
    for i in range(limit):
        fraud_type = random.choice(fraud_types)
        risk_score = random.uniform(0.65, 0.95)
        
        alerts.append(FraudAlertResponse(
            alert_id=i+1,
            transaction_id=f"TXN-{random.randint(10000, 99999)}",
            user_id=f"U{random.randint(1000, 9999)}",
            fraud_type=fraud_type,
            risk_score=round(risk_score, 2),
            risk_level=get_risk_level(risk_score),
            detection_signals={"source": "autoencoder", "confidence": "high"},
            email_sent=True,
            timestamp=datetime.utcnow().isoformat(),
            acknowledged=False
        ))
    
    return alerts

@app.get("/api/v2/alerts/{alert_id}", response_model=FraudAlertResponse)
def get_alert_details(alert_id: int):
    """Get detailed information about a specific alert"""
    return FraudAlertResponse(
        alert_id=alert_id,
        transaction_id=f"TXN-{random.randint(10000, 99999)}",
        user_id=f"U{random.randint(1000, 9999)}",
        fraud_type=random.choice(["sim_swap", "identity_theft", "device_cloning", "mobile_money_fraud"]),
        risk_score=round(random.uniform(0.7, 0.95), 2),
        risk_level="CRITICAL",
        detection_signals={
            "device_anomaly": True,
            "location_change": True,
            "behavioral_deviation": 0.82,
            "reconstruction_error": 0.79
        },
        email_sent=True,
        timestamp=datetime.utcnow().isoformat(),
        acknowledged=False
    )

@app.post("/api/v2/alerts/{alert_id}/acknowledge")
def acknowledge_alert(alert_id: int):
    """Mark alert as acknowledged"""
    return {
        "success": True,
        "alert_id": alert_id,
        "acknowledged": True,
        "timestamp": datetime.utcnow().isoformat()
    }

# ============================================
# TRANSACTION ANALYSIS (UPDATED)
# ============================================

@app.post("/api/analyze")
async def analyze_transaction(
    transaction: dict,
    background_tasks: BackgroundTasks
):
    """Enhanced transaction analysis with all fraud types"""
    
    # Extract transaction data
    user_id = transaction.get("user_id", "U001")
    amount = transaction.get("amount", 0)
    device_id = transaction.get("device_id", f"DEV-{random.randint(1000, 9999)}")
    location = transaction.get("location", "Nairobi")
    
    # Check all fraud types
    sim_swap_score, sim_signals = detect_sim_swap(
        device_is_new=random.random() > 0.7,
        location_changed=random.random() > 0.6,
        time_since_last_auth=random.randint(0, 48),
        failed_pin_count=random.randint(0, 5)
    )
    
    identity_score, id_signals = detect_identity_theft(
        amount_ratio=amount / 2500,
        device_is_new=random.random() > 0.7,
        location_changed=random.random() > 0.6,
        behavior_score=random.uniform(0.3, 0.9),
        document_verified=random.random() > 0.3
    )
    
    # Overall risk score (ensemble)
    risk_score = max(sim_swap_score, identity_score) * 0.7 + 0.3
    
    risk_level = get_risk_level(risk_score)
    alert_needed = risk_score >= 0.65
    
    if alert_needed:
        alert_data = {
            "transaction_id": transaction.get("transaction_id", f"TXN-{random.randint(10000, 99999)}"),
            "user_id": user_id,
            "fraud_type": "multiple",
            "risk_score": risk_score,
            "risk_level": risk_level,
            "amount": amount,
            "reconstruction_error": round(risk_score * 0.9, 2),
            "detection_signals": {
                "sim_swap_score": round(sim_swap_score, 2),
                "identity_theft_score": round(identity_score, 2),
                "device_id": device_id[-4:],
                "location": location
            },
            "timestamp": datetime.utcnow().isoformat()
        }
        background_tasks.add_task(email_service.send_alert, alert_data)
    
    return {
        "transaction_id": transaction.get("transaction_id", f"TXN-{random.randint(10000, 99999)}"),
        "fraud_probability": round(risk_score, 2),
        "risk_level": risk_level,
        "alert_required": alert_needed,
        "amount": amount,
        "user_id": user_id,
        "fraud_types_detected": [
            t for t, s in [("sim_swap", sim_swap_score), ("identity_theft", identity_score)] 
            if s >= 0.6
        ],
        "detection_details": {
            "sim_swap": {"score": round(sim_swap_score, 2), "signals": sim_signals},
            "identity_theft": {"score": round(identity_score, 2), "signals": id_signals}
        },
        "timestamp": datetime.utcnow().isoformat()
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
