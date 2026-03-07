class FraudDetectionEngine:
    def __init__(self):
        self.fraud_types = {
            'SIM_SWAP': {'name': 'SIM Swap', 'risk_level': 'CRITICAL'},
            'IDENTITY_THEFT': {'name': 'Identity Theft', 'risk_level': 'CRITICAL'},
            'DEVICE_CLONING': {'name': 'Device Cloning', 'risk_level': 'CRITICAL'},
            'MOBILE_MONEY_FRAUD': {'name': 'Mobile Money Fraud', 'risk_level': 'HIGH'},
            'AGENT_COLLUSION': {'name': 'Agent Collusion', 'risk_level': 'HIGH'},
            'SOCIAL_ENGINEERING': {'name': 'Social Engineering', 'risk_level': 'MEDIUM'},
            'REPAYMENT_FRAUD': {'name': 'Repayment Fraud', 'risk_level': 'MEDIUM'},
            'SYNTHETIC_IDENTITY': {'name': 'Synthetic Identity', 'risk_level': 'CRITICAL'},
        }

    def analyze_transaction(self, transaction, user_profile):
        return {
            'fraud_type': 'NORMAL',
            'fraud_name': 'Normal Transaction',
            'risk_level': 'LOW',
            'risk_score': 0.2,
            'detection_signals': {}
        }
