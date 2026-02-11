#!/bin/bash
URL="https://fraud-detection-api-production-8293.up.railway.app"

echo "=== QUICK TEST ==="
echo ""

echo "1. Root endpoint:"
curl -s "$URL/"

echo ""
echo ""
echo "2. Fraud types:"
curl -s "$URL/fraud-types"

echo ""
echo ""
echo "3. Predict endpoint:"
curl -X POST "$URL/predict" \
  -H "Content-Type: application/json" \
  -d '{
    "transaction_amount": 15050.61,
    "payment_history_score": 0.71,
    "identity_verification_score": 0.75,
    "device_fingerprint_consistency": 0.98
  }'
