from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Boolean, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

DATABASE_URL = "sqlite:///./fraud.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class Transaction(Base):
    __tablename__ = "transactions"
    id = Column(Integer, primary_key=True, index=True)
    transaction_id = Column(String, unique=True, index=True)
    user_id = Column(String, index=True)
    amount = Column(Float)
    transaction_type = Column(String)
    recipient = Column(String, nullable=True)
    status = Column(String, default="pending")
    timestamp = Column(DateTime, default=datetime.utcnow)

class FraudType(Base):
    __tablename__ = "fraud_types"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True)
    description = Column(String)
    severity = Column(String)
    threshold = Column(Float)
    enabled = Column(Boolean, default=True)

class DeviceFingerprint(Base):
    __tablename__ = "device_fingerprints"
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String, index=True)
    user_id = Column(String, index=True)
    trust_score = Column(Float, default=0.5)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)

class UserLocation(Base):
    __tablename__ = "user_locations"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String, index=True)
    location = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)

class UserBehavior(Base):
    __tablename__ = "user_behaviors"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String, unique=True, index=True)
    avg_transaction_amount = Column(Float, default=2500)
    daily_max = Column(Float, default=25000)
    month_end_max = Column(Float, default=45000)
    trusted_locations = Column(JSON, default=["Nairobi"])
    behavior_score = Column(Float, default=0.5)

class FraudAlert(Base):
    __tablename__ = "fraud_alerts"
    id = Column(Integer, primary_key=True, index=True)
    transaction_id = Column(String, index=True)
    user_id = Column(String, index=True)
    fraud_type = Column(String)
    risk_score = Column(Float)
    reconstruction_error = Column(Float)
    detection_signals = Column(String)
    email_sent = Column(Boolean, default=False)
    email_recipient = Column(String, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    acknowledged = Column(Boolean, default=False)

class EmailConfig(Base):
    __tablename__ = "email_config"
    id = Column(Integer, primary_key=True, index=True)
    recipient_email = Column(String, default="rebeccabosibori589@gmail.com")
    alerts_enabled = Column(Boolean, default=True)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
