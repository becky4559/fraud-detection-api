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
                'icon': 'SW'
            },
            'IDENTITY_THEFT': {
                'name': 'Identity Theft',
                'risk_level': 'CRITICAL',
                'threshold': 0.70,
                'color': '#c00',
                'icon': 'ID'
            },
            'DEVICE_CLONING': {
                'name': 'Device Cloning',
                'risk_level': 'CRITICAL',
                'threshold': 0.80,
                'color': '#c00',
                'icon': 'DC'
            },
            'MOBILE_MONEY_FRAUD': {
                'name': 'Mobile Money Fraud',
                'risk_level': 'HIGH',
                'threshold': 0.65,
                'color': '#f57c00',
                'icon': 'MF'
            },
            'AGENT_COLLUSION': {
                'name': 'Agent Collusion',
                'risk_level': 'HIGH',
                'threshold': 0.70,
                'color': '#f57c00',
                'icon': 'AC'
            },
            'SOCIAL_ENGINEERING': {
                'name': 'Social Engineering',
                'risk_level': 'MEDIUM',
                'threshold': 0.60,
                'color': '#fbc02d',
                'icon': 'SE'
            },
            'REPAYMENT_FRAUD': {
                'name': 'Repayment Fraud',
                'risk_level': 'MEDIUM',
                'threshold': 0.65,
                'color': '#fbc02d',
                'icon': 'RF'
            },
            'SYNTHETIC_IDENTITY': {
                'name': 'Synthetic Identity',
                'risk_level': 'CRITICAL',
                'threshold': 0.85,
                'color': '#c00',
                'icon': 'SI'
            },
            'NORMAL': {
                'name': 'Normal Transaction',
                'risk_level': 'LOW',
                'threshold': 0.20,
                'color': '#2e7d32',
                'icon': 'OK'
            }
        }

        # User time frames (normal active hours)
        self.user_time_frames = {
            'U78901': {'start': 8, 'end': 22},  # John: 8am-10pm
            'U78902': {'start': 9, 'end': 20},  # Mary: 9am-8pm
            'U78903': {'start': 8, 'end': 18},  # Peter: 8am-6pm
        }

        # Track previous flags per user
        self.user_flag_count = {}

    def analyze_transaction(self, transaction, user_profile):
        scores = {}
        signals = {}

        # Get user ID
        user_id = transaction.get('user_id')
        
        # Time anomaly detection
        time_score, time_signals = self.detect_time_anomaly(transaction, user_id)
        if time_score > 0:
            scores['TIME_ANOMALY'] = time_score
            signals['TIME_ANOMALY'] = time_signals

        # Other detections
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

        # Find highest scoring fraud type
        fraud_type = 'NORMAL'
        max_score = 0.2

        for f_type, score in scores.items():
            threshold = self.fraud_types.get(f_type, self.fraud_types['NORMAL'])['threshold']
            if score > threshold and score > max_score:
                max_score = score
                fraud_type = f_type

        # If time anomaly was detected but not highest, still include in signals
        if time_score > 0.4 and fraud_type == 'NORMAL':
            fraud_type = 'SOCIAL_ENGINEERING'
            max_score = max(max_score, time_score)

        # Track flag for Mary's special rule
        if fraud_type != 'NORMAL':
            self.user_flag_count[user_id] = self.user_flag_count.get(user_id, 0) + 1

        return {
            'fraud_type': fraud_type,
            'fraud_name': self.fraud_types.get(fraud_type, self.fraud_types['NORMAL'])['name'],
            'risk_level': self.get_risk_level(max_score, user_id),
            'risk_score': max_score,
            'detection_signals': signals.get(fraud_type, {}),
            'all_scores': scores
        }

    def detect_time_anomaly(self, transaction, user_id):
        """Detect if transaction is outside user's normal hours"""
        try:
            tx_time = datetime.fromisoformat(transaction['timestamp'])
            hour = tx_time.hour
            
            # Get user's normal time frame
            time_frame = self.user_time_frames.get(user_id, {'start': 8, 'end': 20})
            
            # Check if within normal hours
            if hour >= time_frame['start'] and hour < time_frame['end']:
                return 0.2, {}  # Normal time
            
            # Calculate how far outside
            if hour < time_frame['start']:
                hours_off = time_frame['start'] - hour
            else:
                hours_off = hour - time_frame['end']
            
            # Base score for time anomaly
            score = 0.5 + (hours_off * 0.05)
            
            # Mary's special rule: previous flags increase risk
            if user_id == 'U78902' and self.user_flag_count.get(user_id, 0) > 0:
                score += 0.2
                signals = {
                    'time_anomaly': f"Transaction at {hour}:00 (normal hours: {time_frame['start']}-{time_frame['end']})",
                    'previous_flags': self.user_flag_count.get(user_id, 0),
                    'repeat_offender': True
                }
            else:
                signals = {
                    'time_anomaly': f"Transaction at {hour}:00 (normal hours: {time_frame['start']}-{time_frame['end']})"
                }
            
            return min(score, 1.0), signals
            
        except Exception as e:
            print(f"Error in time detection: {e}")
            return 0.2, {}

    def get_risk_level(self, score, user_id):
        """Get risk level with special handling for Mary"""
        base_level = 'LOW'
        if score > 0.7:
            base_level = 'CRITICAL'
        elif score > 0.5:
            base_level = 'HIGH'
        elif score > 0.3:
            base_level = 'MEDIUM'
        
        # Mary's previous flags escalate risk
        if user_id == 'U78902' and self.user_flag_count.get(user_id, 0) > 1:
            if base_level == 'MEDIUM':
                return 'HIGH'
            elif base_level == 'HIGH':
                return 'CRITICAL'
        
        return base_level

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
