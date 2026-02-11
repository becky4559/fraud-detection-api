#!/bin/bash
URL="https://fraud-detection-api-production-8293.up.railway.app"

echo "=== FINAL TEST - YOUR SYSTEM ==="
echo "Time: $(date)"
echo ""

echo "1. API Root (should show 33 features, 8 fraud types):"
curl -s "$URL/"

echo ""
echo ""
echo "2. Fraud Types Endpoint (should list YOUR 8 types):"
curl -s "$URL/fraud-types" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    print('Found', data.get('total_types', 0), 'fraud types:')
    for ft in data.get('fraud_types', []):
        print(f'  - {ft[\"type\"]}: {ft[\"description\"]}')
except:
    print('Could not parse response')
"

echo ""
echo ""
echo "3. Testing with YOUR Social Engineering fraud data (from notebook):"
curl -X POST "$URL/predict" \
  -H "Content-Type: application/json" \
  -d '{
    "transaction_amount": 15050.61,
    "transaction_count_30d": 20,
    "avg_transaction_amount": 752.53,
    "payment_history_score": 0.7123,
    "identity_verification_score": 0.7471,
    "device_fingerprint_consistency": 0.9850,
    "imei_consistency_score": 0.6,
    "days_past_due": 15,
    "login_attempts": 8,
    "failed_attempts": 3,
    "m_pesa_transaction_count": 25,
    "airtime_purchase_frequency": 0.8,
    "fraud_type": "social_engineering"
  }'

echo ""
echo ""
echo "4. Testing with YOUR Legitimate transaction (from notebook):"
curl -X POST "$URL/predict" \
  -H "Content-Type: application/json" \
  -d '{
    "transaction_amount": 2346.34,
    "transaction_count_30d": 5,
    "avg_transaction_amount": 469.27,
    "payment_history_score": 0.6715,
    "identity_verification_score": 0.9811,
    "device_fingerprint_consistency": 0.8244,
    "imei_consistency_score": 0.9,
    "days_past_due": 0,
    "login_attempts": 2,
    "failed_attempts": 0,
    "m_pesa_transaction_count": 3,
    "airtime_purchase_frequency": 0.2,
    "fraud_type": "legitimate"
  }'
