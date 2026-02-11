#!/bin/bash
URL="https://fraud-detection-api-production-8293.up.railway.app"

echo "=== Testing with YOUR ACTUAL DATA from notebook ==="
echo ""

# Test 1: YOUR legitimate transaction (row 0)
echo "1. Legitimate transaction (row 0 from your data):"
curl -X POST "$URL/predict" \
  -H "Content-Type: application/json" \
  -d '{
    "transaction_amount": 2346.34,
    "payment_history_score": 0.6715,
    "identity_verification_score": 0.9811,
    "device_fingerprint_consistency": 0.8244,
    "transaction_count_30d": 5,
    "login_attempts": 2,
    "failed_attempts": 0,
    "imei_consistency_score": 0.9,
    "days_past_due": 0,
    "m_pesa_transaction_count": 3,
    "airtime_purchase_frequency": 0.2,
    "fraud_type": "legitimate"
  }'

echo ""
echo ""
echo "2. Social Engineering fraud (row 1 from your data):"
curl -X POST "$URL/predict" \
  -H "Content-Type: application/json" \
  -d '{
    "transaction_amount": 15050.61,
    "payment_history_score": 0.7123,
    "identity_verification_score": 0.7471,
    "device_fingerprint_consistency": 0.9850,
    "transaction_count_30d": 20,
    "login_attempts": 8,
    "failed_attempts": 3,
    "imei_consistency_score": 0.6,
    "days_past_due": 15,
    "m_pesa_transaction_count": 25,
    "airtime_purchase_frequency": 0.8,
    "fraud_type": "social_engineering"
  }'
