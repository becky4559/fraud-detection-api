from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

# Database URL for SQLite
DATABASE_URL = "sqlite:///./fraud.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class FraudAlert(Base):
    __tablename__ = "fraud_alerts"

    id = Column(Integer, primary_key=True, index=True)
    transaction_id = Column(String, index=True)
    user_name = Column(String, index=True, nullable=True) 
    fraud_type = Column(String)
    fraud_name = Column(String, nullable=True)
    risk_score = Column(Float)
    risk_level = Column(String, nullable=True)
    # Stores the JSON-encoded AI reasoning logs (XAI)
    detection_signals = Column(Text, nullable=True)  
    amount = Column(Float, nullable=True)
    recipient = Column(String, nullable=True)
    location = Column(String, nullable=True)
    # Use datetime.now (local system time) for the demo so it matches your watch/phone
    timestamp = Column(DateTime, default=datetime.now, index=True)
    acknowledged = Column(Boolean, default=False)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Create tables if they don't exist
Base.metadata.create_all(bind=engine)
