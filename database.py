# database.py
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

# SQLite database (file-based)
DATABASE_URL = "sqlite:///./fraud.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class Transaction(Base):
    __tablename__ = "transactions"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String, index=True)
    amount = Column(Float)
    fraud_probability = Column(Float)
    risk_level = Column(String)
    alert_required = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=datetime.utcnow)

class FraudType(Base):
    __tablename__ = "fraud_types"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    description = Column(String)
    severity = Column(String)

# Create tables
Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ============================================
# NEW TABLES FOR ENHANCED FRAUD DETECTION
# ============================================

class DeviceFingerprint(Base):
    __tablename__ = "device_fingerprints"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String, index=True)
    device_id = Column(String, index=True)
    device_name = Column(String)
    browser = Column(String)
    os = Column(String)
    screen_resolution = Column(String)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    is_trusted = Column(Boolean, default=False)

class UserLocation(Base):
    __tablename__ = "user_locations"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String, index=True)
    latitude = Column(Float)
    longitude = Column(Float)
    city = Column(String)
    country = Column(String)
    ip_address = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)
    is_usual = Column(Boolean, default=False)

class UserBehavior(Base):
    __tablename__ = "user_behavior"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String, index=True)
    avg_transaction_amount = Column(Float, default=0)
    transaction_count_7d = Column(Integer, default=0)
    usual_transaction_hours = Column(String)  # JSON string of hours
    usual_locations = Column(String)  # JSON string of location IDs
    usual_devices = Column(String)  # JSON string of device IDs
    last_updated = Column(DateTime, default=datetime.utcnow)

class FraudAlert(Base):
    __tablename__ = "fraud_alerts"

    id = Column(Integer, primary_key=True, index=True)
    transaction_id = Column(Integer, index=True)
    user_id = Column(String, index=True)
    fraud_type = Column(String)  # sim_swap, identity_theft, etc.
    risk_score = Column(Float)
    reconstruction_error = Column(Float)  # From autoencoder
    detection_signals = Column(String)  # JSON of what triggered the alert
    email_sent = Column(Boolean, default=False)
    email_recipient = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)
    acknowledged = Column(Boolean, default=False)

class EmailConfig(Base):
    __tablename__ = "email_config"

    id = Column(Integer, primary_key=True, index=True)
    recipient_email = Column(String, default="rebeccabosibori589@gmail.com")
    alerts_enabled = Column(Boolean, default=True)
    last_updated = Column(DateTime, default=datetime.utcnow)
