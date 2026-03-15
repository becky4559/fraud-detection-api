# models.py
from pydantic import BaseModel
from typing import Optional

class TransactionResponse(BaseModel):
    transaction_id: int
    fraud_probability: float
    risk_level: str
    alert_required: bool
    amount: float
    user_id: str
    timestamp: str

class FraudTypeResponse(BaseModel):
    name: str
    description: str
    severity: str

class StatsResponse(BaseModel):
    total_transactions: int
    high_risk_transactions: int
    fraud_types_configured: int
    timestamp: str

# ============================================
# ENHANCED FRAUD DETECTION MODELS
# ============================================

class SimSwapRequest(BaseModel):
    user_id: str
    transaction_id: Optional[str] = None
    device_id: str
    location_city: str
    location_country: str
    ip_address: Optional[str] = None
    failed_pin_attempts: int = 0
    phone_number: Optional[str] = None
    timestamp: Optional[str] = None

class SimSwapResponse(BaseModel):
    fraud_type: str = "sim_swap"
    risk_score: float
    risk_level: str
    alert_required: bool
    detection_signals: dict
    reconstruction_error: Optional[float] = None
    timestamp: str

class IdentityTheftRequest(BaseModel):
    user_id: str
    transaction_id: Optional[str] = None
    amount: float
    avg_transaction_amount: Optional[float] = None
    device_id: str
    location_city: str
    location_country: str
    document_verified: bool = False
    behavior_score: Optional[float] = 0.5
    timestamp: Optional[str] = None

class IdentityTheftResponse(BaseModel):
    fraud_type: str = "identity_theft"
    risk_score: float
    risk_level: str
    alert_required: bool
    detection_signals: dict
    reconstruction_error: Optional[float] = None
    timestamp: str

class DeviceCloningRequest(BaseModel):
    user_id: str
    transaction_id: Optional[str] = None
    device_id: str
    ip_address: Optional[str] = None
    timestamp: Optional[str] = None

class DeviceCloningResponse(BaseModel):
    fraud_type: str = "device_cloning"
    risk_score: float
    risk_level: str
    alert_required: bool
    detection_signals: dict
    active_locations: list = []
    device_rooted: bool = False
    app_tampered: bool = False
    timestamp: str

class MobileFraudRequest(BaseModel):
    user_id: str
    transaction_id: Optional[str] = None
    amount: float
    avg_transaction_amount: Optional[float] = None
    recipient_count: int = 1
    transaction_count_5min: int = 1
    device_trust_score: Optional[float] = 0.5
    timestamp: Optional[str] = None

class MobileFraudResponse(BaseModel):
    fraud_type: str = "mobile_money_fraud"
    risk_score: float
    risk_level: str
    alert_required: bool
    detection_signals: dict
    velocity_5min: int
    unique_recipients: int
    reconstruction_error: Optional[float] = None
    timestamp: str

class EmailConfigResponse(BaseModel):
    recipient_email: str
    alerts_enabled: bool
    last_updated: str

class EmailTestResponse(BaseModel):
    success: bool
    recipient: str
    sent_at: str
    message: str

class FraudAlertResponse(BaseModel):
    alert_id: int
    transaction_id: str
    user_id: str
    fraud_type: str
    risk_score: float
    risk_level: str
    detection_signals: dict
    email_sent: bool
    timestamp: str
    acknowledged: bool = False

class UserBehaviorProfile(BaseModel):
    user_id: str
    avg_transaction_amount: float
    transaction_count_7d: int
    usual_hours: list
    usual_locations: list
    usual_devices: list
    risk_trend: Optional[str] = None
