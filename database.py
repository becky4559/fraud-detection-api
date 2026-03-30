from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

# SQLite database file path
SQLALCHEMY_DATABASE_URL = "sqlite:///./fraud.db"

# Create the engine
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class FraudAlert(Base):
    __tablename__ = "fraud_alerts"

    id = Column(Integer, primary_key=True, index=True)
    transaction_id = Column(String, unique=True, index=True)
    user_name = Column(String)
    fraud_type = Column(String) # e.g., DEVICE_CLONING
    fraud_name = Column(String) # e.g., Mobile Device Cloning
    risk_score = Column(Float)
    risk_level = Column(String) # CRITICAL or HIGH
    amount = Column(Float)
    recipient = Column(String)
    location = Column(String)
    
    # Store the JSON technical metadata and AI reasoning here
    detection_signals = Column(Text) 
    
    timestamp = Column(DateTime, default=datetime.now)

# Database dependency for FastAPI
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Create tables immediately upon import
Base.metadata.create_all(bind=engine)
