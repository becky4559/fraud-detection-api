"""
Mock Services for External Integrations
These simulate APIs from telecom providers, biometric vendors, and device intelligence platforms
For demo purposes only - not actual integrations
"""

import random
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional

# ============================================
# MOCK TELECOM PROVIDER API (Safaricom/Airtel/Telkom)
# ============================================

class MockTelecomAPI:
    """Simulates carrier APIs for SIM swap detection"""
    
    @staticmethod
    def check_sim_status(phone_number: str) -> Dict:
        """
        Mock endpoint: GET /api/v1/carrier/sim-status
        Returns SIM swap information
        """
        # Simulate different scenarios based on phone number
        last_digit = int(phone_number[-1]) if phone_number[-1].isdigit() else 0
        
        if last_digit in [0, 1, 2]:
            # SIM recently changed
            return {
                "phone_number": phone_number,
                "sim_changed": True,
                "changed_at": (datetime.utcnow() - timedelta(hours=2)).isoformat(),
                "previous_carrier": "Safaricom",
                "new_carrier": "Airtel",
                "swap_method": "USSD",
                "location_at_swap": "Nairobi, Kenya"
            }
        elif last_digit in [3, 4, 5]:
            # SIM changed recently but verified
            return {
                "phone_number": phone_number,
                "sim_changed": True,
                "changed_at": (datetime.utcnow() - timedelta(days=5)).isoformat(),
                "previous_carrier": "Airtel",
                "new_carrier": "Safaricom",
                "swap_method": "Agent",
                "location_at_swap": "Mombasa, Kenya",
                "verified": True
            }
        else:
            # No SIM change
            return {
                "phone_number": phone_number,
                "sim_changed": False,
                "carrier": "Safaricom",
                "sim_age_days": random.randint(30, 365)
            }
    
    @staticmethod
    def check_failed_pin_attempts(phone_number: str, hours: int = 24) -> Dict:
        """
        Mock endpoint: GET /api/v1/carrier/pin-attempts
        Returns failed PIN attempt history
        """
        attempts = random.choices([0, 1, 2, 3, 4, 5], weights=[40, 25, 15, 10, 5, 5])[0]
        
        return {
            "phone_number": phone_number,
            "failed_attempts_24h": attempts,
            "last_attempt": (datetime.utcnow() - timedelta(minutes=random.randint(5, 120))).isoformat() if attempts > 0 else None,
            "account_locked": attempts >= 5,
            "lockout_end": (datetime.utcnow() + timedelta(minutes=30)).isoformat() if attempts >= 5 else None
        }


# ============================================
# MOCK BIOMETRIC VERIFICATION API
# ============================================

class MockBiometricAPI:
    """Simulates biometric verification services"""
    
    @staticmethod
    def verify_identity(user_id: str, verification_type: str = "face") -> Dict:
        """
        Mock endpoint: POST /api/v1/biometric/verify
        Simulates face/fingerprint matching
        """
        # Deterministic based on user_id to create consistent demos
        user_hash = sum(ord(c) for c in user_id) % 100
        
        if user_hash < 30:
            # Strong match
            return {
                "user_id": user_id,
                "verification_type": verification_type,
                "match_score": random.uniform(0.92, 0.99),
                "threshold": 0.75,
                "verified": True,
                "confidence": "HIGH",
                "processing_time_ms": random.randint(150, 350),
                "timestamp": datetime.utcnow().isoformat()
            }
        elif user_hash < 60:
            # Weak match
            return {
                "user_id": user_id,
                "verification_type": verification_type,
                "match_score": random.uniform(0.65, 0.74),
                "threshold": 0.75,
                "verified": False,
                "confidence": "LOW",
                "processing_time_ms": random.randint(200, 400),
                "timestamp": datetime.utcnow().isoformat(),
                "fallback_available": True
            }
        else:
            # Failed match
            return {
                "user_id": user_id,
                "verification_type": verification_type,
                "match_score": random.uniform(0.10, 0.45),
                "threshold": 0.75,
                "verified": False,
                "confidence": "FAILED",
                "processing_time_ms": random.randint(300, 600),
                "timestamp": datetime.utcnow().isoformat(),
                "attempts_remaining": 2
            }
    
    @staticmethod
    def verify_document(document_type: str, document_number: str) -> Dict:
        """
        Mock endpoint: POST /api/v1/kyc/verify-document
        Simulates ID document verification
        """
        # Check document format validity
        is_valid_format = len(document_number) > 5
        
        return {
            "document_type": document_type,
            "document_number": document_number[-4:].rjust(len(document_number), '*'),
            "format_valid": is_valid_format,
            "expiry_valid": random.choice([True, True, True, False]),
            "fraud_database_check": random.choice(["clean", "clean", "clean", "suspicious"]),
            "verification_status": "VERIFIED" if is_valid_format and random.random() > 0.2 else "REJECTED",
            "confidence_score": random.uniform(0.70, 0.98) if is_valid_format else random.uniform(0.20, 0.45),
            "timestamp": datetime.utcnow().isoformat()
        }


# ============================================
# MOCK DEVICE INTELLIGENCE API
# ============================================

class MockDeviceAPI:
    """Simulates device fingerprinting and intelligence"""
    
    @staticmethod
    def check_device(device_id: str, ip_address: str = None) -> Dict:
        """
        Mock endpoint: POST /api/v1/device/intelligence
        Returns device risk assessment
        """
        # Simulate device risk factors
        device_hash = sum(ord(c) for c in device_id) % 100
        
        active_locations = []
        if device_hash < 40:
            # Clean device
            active_locations.append({
                "ip": ip_address or "192.168.1.1",
                "city": "Nairobi",
                "country": "Kenya",
                "last_seen": datetime.utcnow().isoformat()
            })
            rooted = False
            tampered = False
            risk = "LOW"
        elif device_hash < 70:
            # Suspicious device
            active_locations = [
                {
                    "ip": "41.80.0.1",
                    "city": "Nairobi",
                    "country": "Kenya",
                    "last_seen": (datetime.utcnow() - timedelta(minutes=5)).isoformat()
                },
                {
                    "ip": "105.20.0.1",
                    "city": "Lagos",
                    "country": "Nigeria",
                    "last_seen": (datetime.utcnow() - timedelta(minutes=2)).isoformat()
                }
            ]
            rooted = random.choice([True, False])
            tampered = random.choice([True, False])
            risk = "HIGH"
        else:
            # High risk device
            active_locations = [
                {
                    "ip": "197.200.0.1",
                    "city": "Mombasa",
                    "country": "Kenya",
                    "last_seen": (datetime.utcnow() - timedelta(minutes=10)).isoformat()
                },
                {
                    "ip": "102.80.0.1",
                    "city": "Johannesburg",
                    "country": "South Africa",
                    "last_seen": (datetime.utcnow() - timedelta(minutes=3)).isoformat()
                },
                {
                    "ip": "41.90.0.1",
                    "city": "Kampala",
                    "country": "Uganda",
                    "last_seen": (datetime.utcnow() - timedelta(minutes=1)).isoformat()
                }
            ]
            rooted = True
            tampered = True
            risk = "CRITICAL"
        
        return {
            "device_id": device_id,
            "device_name": f"Android-{random.randint(10, 14)}",
            "model": f"Tecno-{random.randint(1000, 9999)}",
            "rooted": rooted,
            "app_tampered": tampered,
            "emulator": random.random() < 0.1,
            "active_locations": active_locations,
            "location_count": len(active_locations),
            "risk_level": risk,
            "trust_score": random.uniform(0.2, 0.9) if risk != "LOW" else random.uniform(0.8, 0.99),
            "first_seen": (datetime.utcnow() - timedelta(days=random.randint(1, 90))).isoformat(),
            "timestamp": datetime.utcnow().isoformat()
        }


# ============================================
# MOCK FRAUD DATABASE CHECKS
# ============================================

class MockFraudDatabase:
    """Simulates fraud intelligence databases"""
    
    @staticmethod
    def check_phone_risk(phone_number: str) -> Dict:
        """Check if phone number appears in fraud reports"""
        risk_score = random.uniform(0.1, 0.9)
        
        return {
            "phone_number": phone_number,
            "risk_score": risk_score,
            "risk_level": "HIGH" if risk_score > 0.7 else "MEDIUM" if risk_score > 0.4 else "LOW",
            "reports_last_30d": random.randint(0, 5),
            "associated_fraud_types": random.sample(["sim_swap", "social_engineering", "identity_theft"], 
                                                   k=random.randint(0, 2)),
            "last_report": (datetime.utcnow() - timedelta(days=random.randint(1, 30))).isoformat() if risk_score > 0.5 else None
        }
    
    @staticmethod
    def check_ip_risk(ip_address: str) -> Dict:
        """Check if IP address is associated with fraud"""
        return {
            "ip_address": ip_address,
            "proxy": random.random() < 0.2,
            "vpn": random.random() < 0.15,
            "tor": random.random() < 0.05,
            "datacenter": random.random() < 0.3,
            "abuse_score": random.uniform(0, 0.8),
            "country": random.choice(["KE", "NG", "ZA", "GH", "TZ"]),
            "fraud_reports": random.randint(0, 3)
        }
