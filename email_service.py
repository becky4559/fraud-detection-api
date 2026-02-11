"""
Email Alert Service - Clean Version
Simulates sending fraud alerts to configured email
"""

import logging
from datetime import datetime
from typing import Dict, Optional

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DEFAULT_RECIPIENT = "rebeccabosibori589@gmail.com"

class EmailService:
    def __init__(self, recipient_email: str = DEFAULT_RECIPIENT):
        self.recipient_email = recipient_email
        self.alerts_enabled = True

    def send_alert(self, fraud_data: Dict) -> Dict:
        logger.info(f"í³§ Alert sent to {self.recipient_email}")
        return {
            "success": True,
            "recipient": self.recipient_email,
            "sent_at": datetime.utcnow().isoformat()
        }

email_service = EmailService()
