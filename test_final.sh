#!/bin/bash
URL="https://fraud-detection-api-production-8293.up.railway.app"

echo "=== Testing YOUR 33 features API ==="
echo ""

echo "1. Getting fraud types:"
curl -s "$URL/fraud-types" | python3 -m json.tool

echo ""
echo "2. Testing with YOUR Social Engineering fraud data:"
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
