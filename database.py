from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

# Using the same filename as your PyCharm project setup
DATABASE_URL = "sqlite:///./fraud.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class FraudAlert(Base):
    __tablename__ = "fraud_alerts"

    id = Column(Integer, primary_key=True, index=True)
    transaction_id = Column(String, index=True)
    # Changed user_id to user_name to match app.py logic
    user_name = Column(String, index=True, nullable=True) 
    fraud_type = Column(String)
    fraud_name = Column(String, nullable=True)
    risk_score = Column(Float)
    risk_level = Column(String, nullable=True)
    # Changed to Text to ensure long JSON strings don't get cut off
    detection_signals = Column(Text, nullable=True)  
    amount = Column(Float, nullable=True)
    recipient = Column(String, nullable=True)
    location = Column(String, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    acknowledged = Column(Boolean, default=False)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

Base.metadata.create_all(bind=engine)
