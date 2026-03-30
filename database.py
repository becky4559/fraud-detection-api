from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

DATABASE_URL = "sqlite:///./fraud.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class FraudAlert(Base):
    __tablename__ = "fraud_alerts"
    id = Column(Integer, primary_key=True, index=True)
    transaction_id = Column(String)
    user_name = Column(String)
    fraud_name = Column(String)
    risk_level = Column(String)
    amount = Column(Float)
    recipient = Column(String)
    location = Column(String)
    detection_signals = Column(Text) # JSON stored here
    timestamp = Column(DateTime, default=datetime.now)

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

Base.metadata.create_all(bind=engine)
