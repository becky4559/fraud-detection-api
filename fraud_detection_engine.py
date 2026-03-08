class FraudDetectionEngine:
    def analyze_transaction(self, transaction, profile):
        return {
            'fraud_type': 'SIM_SWAP',
            'fraud_name': 'SIM Swap',
            'risk_level': 'HIGH',
            'risk_score': 0.85,
            'detection_signals': {},
            'all_scores': {}
        }
