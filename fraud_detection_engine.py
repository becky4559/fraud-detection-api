import json
from datetime import datetime, timedelta
import random

class FraudDetectionEngine:
    def __init__(self):
        self.fraud_types = {
            'SIM_SWAP': {
                'name': 'SIM Swap',
                'risk_level': 'CRITICAL',
                'threshold': 0.75,
                'color': '#c00',
                'icon': 'í³±'
            },
            'IDENTITY_THEFT': {
                'name': 'Identity Theft',
                'risk_level': 'CRITICAL',
                'threshold': 0.70,
                'color': '#c00',
                'icon': 'í¶”'
            },
            'DEVICE_CLONING': {
                'name': 'Device Cloning',
                'risk_level': 'CRITICAL',
                'threshold': 0.80,
                'color': '#c00',
                'icon': 'ï¿½ï¿½'
            },
            'MOBILE_MONEY_FRAUD': {
                'name': 'Mobile Money Fraud',
                'risk_level': 'HIGH',
                'threshold': 0.65,
                'color': '#f57c00',
                'icon': 'í²°'
            },
            'AGENT_COLLUSION': {
                'name': 'Agent Collusion',
                'risk_level': 'HIGH',
                'threshold': 0.70,
                'color': '#f57c00',
                'icon': 'í±¥'
            },
            'SOCIAL_ENGINEERING': {
                'name': 'Social Engineering',
                'risk_level': 'MEDIUM',
                'threshold': 0.60,
                'color': '#fbc02d',
                'icon': 'í¾£'
            },
            'REPAYMENT_FRAUD': {
                'name': 'Repayment Fraud',
                'risk_level': 'MEDIUM',
                'threshold': 0.65,
                'color': '#fbc02d',
                'icon': 'í´„'
            },
            'SYNTHETIC_IDENTITY': {
                'name': 'Synthetic Identity',
                'risk_level': 'CRITICAL',
                'threshold': 0.85,
                'color': '#c00',
                'icon': 'í¾­'
            },
            'NORMAL': {
                'name': 'Normal Transaction',
                'risk_level': 'LOW',
                'threshold': 0.20,
                'color': '#2e7d32',
                'icon': 'âœ…'
            }
        }

    def analyze_transaction(self, transaction, user_profile):
        scores = {}
        signals = {}

        sim_swap_score, sim_signals = self.detect_sim_swap(transaction, user_profile)
        scores['SIM_SWAP'] = sim_swap_score
        signals['SIM_SWAP'] = sim_signals

        identity_score, identity_signals = self.detect_identity_theft(transaction, user_profile)
        scores['IDENTITY_THEFT'] = identity_score
        signals['IDENTITY_THEFT'] = identity_signals

        cloning_score, cloning_signals = self.detect_device_cloning(transaction, user_profile)
        scores['DEVICE_CLONING'] = cloning_score
        signals['DEVICE_CLONING'] = cloning_signals

        mobile_score, mobile_signals = self.detect_mobile_fraud(transaction, user_profile)
        scores['MOBILE_MONEY_FRAUD'] = mobile_score
        signals['MOBILE_MONEY_FRAUD'] = mobile_signals

        agent_score, agent_signals = self.detect_agent_collusion(transaction, user_profile)
        scores['AGENT_COLLUSION'] = agent_score
        signals['AGENT_COLLUSION'] = agent_signals

        social_score, social_signals = self.detect_social_engineering(transaction, user_profile)
        scores['SOCIAL_ENGINEERING'] = social_score
        signals['SOCIAL_ENGINEERING'] = social_signals

        repayment_score, repayment_signals = self.detect_repayment_fraud(transaction, user_profile)
        scores['REPAYMENT_FRAUD'] = repayment_score
        signals['REPAYMENT_FRAUD'] = repayment_signals

        synthetic_score, synthetic_signals = self.detect_synthetic_identity(transaction, user_profile)
        scores['SYNTHETIC_IDENTITY'] = synthetic_score
        signals['SYNTHETIC_IDENTITY'] = synthetic_signals

        fraud_type = 'NORMAL'
        max_score = 0.2

        for f_type, score in scores.items():
            threshold = self.fraud_types[f_type]['threshold']
            if score > threshold and score > max_score:
                max_score = score
                fraud_type = f_type

        return {
            'fraud_type': fraud_type,
            'fraud_name': self.fraud_types[fraud_type]['name'],
            'risk_level': self.fraud_types[fraud_type]['risk_level'],
            'risk_score': max_score,
            'detection_signals': signals[fraud_type] if fraud_type != 'NORMAL' else {},
            'all_scores': scores
        }

    def detect_sim_swap(self, transaction, profile):
        score = 0.2
        signals = {}

        if transaction.get('device_id') not in profile.get('known_devices', []):
            score += 0.3
            signals['new_device'] = True

        if transaction.get('location') not in profile.get('known_locations', []):
            score += 0.2
            signals['new_location'] = True

        last_location = profile.get('last_location')
        last_time = profile.get('last_transaction_time')
        if last_location and last_time:
            if last_location != transaction.get('location'):
                try:
                    time_diff = datetime.now() - datetime.fromisoformat(last_time)
                    if time_diff.total_seconds() < 3600:
                        score += 0.3
                        signals['impossible_travel'] = True
                except:
                    pass

        if profile.get('recent_failed_pins', 0) > 2:
            score += 0.2
            signals['failed_pins'] = profile['recent_failed_pins']

        return min(score, 1.0), signals

    def detect_identity_theft(self, transaction, profile):
        score = 0.2
        signals = {}

        avg_amount = profile.get('avg_amount', 25000)
        if transaction['amount'] > avg_amount * 10:
            score += 0.4
            signals['amount_ratio'] = transaction['amount'] / avg_amount

        if transaction.get('recipient') not in profile.get('frequent_recipients', []):
            score += 0.2
            signals['new_recipient'] = True

        try:
            transaction_hour = datetime.fromisoformat(transaction['timestamp']).hour
            normal_hours = profile.get('active_hours', list(range(8, 21)))
            if transaction_hour not in normal_hours:
                score += 0.2
                signals['unusual_time'] = transaction_hour
        except:
            pass

        if profile.get('unique_recipients_5min', 0) > 3:
            score += 0.2
            signals['multiple_recipients'] = profile['unique_recipients_5min']

        return min(score, 1.0), signals

    def detect_device_cloning(self, transaction, profile):
        score = 0.2
        signals = {}

        if profile.get('device_active_elsewhere', False):
            score += 0.6
            signals['device_active_elsewhere'] = True

        if transaction.get('device_rooted', False):
            score += 0.3
            signals['device_rooted'] = True

        if transaction.get('app_tampered', False):
            score += 0.3
            signals['app_tampered'] = True

        return min(score, 1.0), signals

    def detect_mobile_fraud(self, transaction, profile):
        score = 0.2
        signals = {}

        if profile.get('transaction_count_5min', 0) > 5:
            score += 0.4
            signals['high_velocity'] = profile['transaction_count_5min']

        if profile.get('unique_recipients_5min', 0) > 3:
            score += 0.3
            signals['many_recipients'] = profile['unique_recipients_5min']

        if transaction['amount'] % 1000 == 0 and transaction['amount'] > 10000:
            score += 0.2
            signals['round_amount'] = transaction['amount']

        return min(score, 1.0), signals

    def detect_agent_collusion(self, transaction, profile):
        score = 0.2
        signals = {}

        if transaction.get('is_agent', False):
            score += 0.3
            signals['agent_involved'] = True

        if transaction.get('transaction_type') == 'cash_out' and transaction['amount'] > 50000:
            score += 0.3
            signals['large_cash_out'] = transaction['amount']

        if transaction.get('agent_id') not in profile.get('known_agents', []):
            score += 0.2
            signals['new_agent'] = True

        return min(score, 1.0), signals

    def detect_social_engineering(self, transaction, profile):
        score = 0.2
        signals = {}

        if transaction.get('recipient') not in profile.get('frequent_recipients', []):
            score += 0.3
            signals['new_beneficiary'] = True

        avg_amount = profile.get('avg_amount', 25000)
        if transaction['amount'] > avg_amount * 3:
            score += 0.3
            signals['amount_ratio'] = transaction['amount'] / avg_amount

        urgent_words = ['urgent', 'emergency', 'immediately', 'quick', 'now', 'please help']
        note = transaction.get('note', '').lower()
        for word in urgent_words:
            if word in note:
                score += 0.2
                signals['urgent_keyword'] = word
                break

        return min(score, 1.0), signals

    def detect_repayment_fraud(self, transaction, profile):
        score = 0.2
        signals = {}

        recent = profile.get('recent_transactions', [])
        if len(recent) >= 2:
            if self.is_circular_pattern(transaction, recent):
                score += 0.5
                signals['circular_pattern'] = True

        if transaction.get('repayment_amount') and transaction['amount'] != transaction['repayment_amount']:
            score += 0.3
            signals['amount_mismatch'] = True

        return min(score, 1.0), signals

    def detect_synthetic_identity(self, transaction, profile):
        score = 0.2
        signals = {}

        account_age = profile.get('account_age_days', 365)
        if account_age < 7:
            score += 0.4
            signals['new_account'] = account_age

        if profile.get('transaction_count', 0) == 1 and transaction['amount'] > 50000:
            score += 0.3
            signals['first_transaction_large'] = transaction['amount']

        if not profile.get('has_credit_history', False):
            score += 0.2
            signals['no_credit_history'] = True

        return min(score, 1.0), signals

    def is_circular_pattern(self, transaction, recent):
        return False

    def build_user_profile(self, user_id, transactions):
        if not transactions:
            return {
                'user_id': user_id,
                'avg_amount': 25000,
                'known_locations': ['Nairobi'],
                'known_devices': [],
                'frequent_recipients': [],
                'active_hours': list(range(8, 21)),
                'transaction_count': 0,
                'account_age_days': 0
            }

        amounts = [t['amount'] for t in transactions if t['amount'] > 0]
        locations = list(set([t.get('location', 'Nairobi') for t in transactions]))
        recipients = list(set([t.get('recipient') for t in transactions if t.get('recipient')]))
        devices = list(set([t.get('device_id') for t in transactions if t.get('device_id')]))

        if amounts:
            avg_amount = sum(amounts) / len(amounts)
        else:
            avg_amount = 25000

        hours = []
        for t in transactions:
            try:
                hour = datetime.fromisoformat(t['timestamp']).hour
                hours.append(hour)
            except:
                pass

        if hours:
            active_hours = list(set(hours))
        else:
            active_hours = list(range(8, 21))

        return {
            'user_id': user_id,
            'avg_amount': avg_amount,
            'known_locations': locations if locations else ['Nairobi'],
            'known_devices': devices,
            'frequent_recipients': recipients[:10],
            'active_hours': active_hours,
            'transaction_count': len(transactions),
            'account_age_days': self.calculate_account_age(transactions)
        }

    def calculate_account_age(self, transactions):
        if not transactions:
            return 0
        try:
            first_tx = min([datetime.fromisoformat(t['timestamp']) for t in transactions])
            return (datetime.now() - first_tx).days
        except:
            return 0
