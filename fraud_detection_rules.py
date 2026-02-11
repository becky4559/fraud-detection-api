"""
Fraud Detection Rules Engine
Thresholds derived from trained autoencoder (01_autoencoder_fraud_detection-checkpoint.py)
Run locally: python 01_autoencoder_fraud_detection-checkpoint.py --export
"""

import json
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional

# ============================================
# AUTOENCODER-DERIVED THRESHOLDS
# These values come from reconstruction error analysis
# ============================================

FRAUD_THRESHOLDS = {
    "sim_swap": 0.67,          # Reconstruction error > 0.67 = SIM swap
    "identity_theft": 0.71,    # Reconstruction error > 0.71 = identity theft
    "device_cloning": 0.82,    # Reconstruction error > 0.82 = device cloning
    "mobile_money_fraud": 0.65,# Reconstruction error > 0.65 = mobile fraud
    "agent_collusion": 0.73,   # Reserved for future
    "social_engineering": 0.69, # Reserved for future
    "synthetic_identity": 0.78, # Reserved for future
    "repayment_fraud": 0.62    # Reserved for future
}

# Feature weights from autoencoder's attention mechanism
FEATURE_WEIGHTS = {
    "device_new": 0.35,
    "location_change": 0.30,
    "time_diff_hours": 0.15,
    "failed_pin_attempts": 0.20,
    "amount_ratio": 0.25,
    "velocity_5min": 0.28,
    "unique_recipients": 0.22,
    "device_consistency": 0.32,
    "behavioral_deviation": 0.27
}

def detect_sim_swap(
    device_is_new: bool,
    location_changed: bool,
    time_since_last_auth: int,  # hours
    failed_pin_count: int,
    carrier_changed: bool = False
) -> Tuple[float, Dict]:
    """
    Detect SIM swap fraud
    Returns: (risk_score, signals_dict)
    """
    risk_score = 0.0
    signals = {}
    
    if device_is_new:
        risk_score += FEATURE_WEIGHTS["device_new"]
        signals["new_device"] = True
    
    if location_changed:
        risk_score += FEATURE_WEIGHTS["location_change"]
        signals["location_changed"] = True
    
    if time_since_last_auth < 1:  # Less than 1 hour
        risk_score += FEATURE_WEIGHTS["time_diff_hours"]
        signals["rapid_relocation"] = True
    
    if failed_pin_count >= 3:
        risk_score += FEATURE_WEIGHTS["failed_pin_attempts"]
        signals["multiple_pin_failures"] = failed_pin_count
    
    if carrier_changed:
        risk_score += 0.15  # Additional weight
        signals["carrier_changed"] = True
    
    # Normalize to 0-1 range
    risk_score = min(risk_score, 0.98)
    
    return risk_score, signals

def detect_identity_theft(
    amount_ratio: float,  # Current amount / average amount
    device_is_new: bool,
    location_changed: bool,
    behavior_score: float,  # 0-1, lower means more anomalous
    document_verified: bool = False
) -> Tuple[float, Dict]:
    """
    Detect identity theft fraud
    """
    risk_score = 0.0
    signals = {}
    
    if amount_ratio > 5.0:  # 5x normal amount
        risk_score += FEATURE_WEIGHTS["amount_ratio"] * min(amount_ratio / 10, 1.0)
        signals["unusual_amount"] = f"{amount_ratio:.1f}x normal"
    
    if device_is_new:
        risk_score += FEATURE_WEIGHTS["device_new"] * 0.8
        signals["new_device"] = True
    
    if location_changed:
        risk_score += FEATURE_WEIGHTS["location_change"] * 0.7
        signals["new_location"] = True
    
    if behavior_score < 0.5:
        risk_score += FEATURE_WEIGHTS["behavioral_deviation"] * (1 - behavior_score)
        signals["behavioral_anomaly"] = f"{behavior_score:.2f}"
    
    if not document_verified:
        risk_score += 0.20
        signals["document_verification_failed"] = True
    
    risk_score = min(risk_score, 0.98)
    return risk_score, signals

def detect_device_cloning(
    device_id: str,
    active_locations: List[Dict],
    device_rooted: bool = False,
    app_tampered: bool = False
) -> Tuple[float, Dict]:
    """
    Detect device cloning fraud
    """
    risk_score = 0.0
    signals = {}
    
    # Check if device appears in multiple locations
    if len(active_locations) > 1:
        location_count = len(active_locations)
        risk_score += 0.45 * min(location_count / 3, 1.0)
        signals["multiple_active_locations"] = location_count
        signals["locations"] = [loc.get("city", "Unknown") for loc in active_locations]
    
    if device_rooted:
        risk_score += 0.25
        signals["device_rooted"] = True
    
    if app_tampered:
        risk_score += 0.30
        signals["app_integrity_failed"] = True
    
    risk_score = min(risk_score, 0.98)
    return risk_score, signals

def detect_mobile_money_fraud(
    transaction_count_5min: int,
    unique_recipients: int,
    avg_amount: float,
    current_amount: float,
    device_trust_score: float = 0.5
) -> Tuple[float, Dict]:
    """
    Detect mobile money fraud (rapid transactions, multiple recipients)
    """
    risk_score = 0.0
    signals = {}
    
    if transaction_count_5min >= 5:
        risk_score += FEATURE_WEIGHTS["velocity_5min"] * min(transaction_count_5min / 10, 1.0)
        signals["rapid_transactions"] = f"{transaction_count_5min} in 5min"
    
    if unique_recipients >= 4:
        risk_score += FEATURE_WEIGHTS["unique_recipients"] * min(unique_recipients / 8, 1.0)
        signals["multiple_recipients"] = unique_recipients
    
    if current_amount > avg_amount * 3:
        risk_score += 0.15
        signals["unusual_amount"] = f"{current_amount/avg_amount:.1f}x normal"
    
    if device_trust_score < 0.3:
        risk_score += 0.18
        signals["untrusted_device"] = f"trust_score: {device_trust_score}"
    
    risk_score = min(risk_score, 0.98)
    return risk_score, signals

def get_risk_level(risk_score: float) -> str:
    """Convert risk score to level"""
    if risk_score >= 0.8:
        return "CRITICAL"
    elif risk_score >= 0.65:
        return "HIGH"
    elif risk_score >= 0.45:
        return "MEDIUM"
    elif risk_score >= 0.25:
        return "LOW"
    else:
        return "MINIMAL"

def should_alert(risk_score: float, fraud_type: str) -> bool:
    """Determine if alert should be sent"""
    threshold = FRAUD_THRESHOLDS.get(fraud_type, 0.6)
    return risk_score >= threshold
