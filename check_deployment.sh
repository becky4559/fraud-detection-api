#!/bin/bash
URL="https://fraud-detection-api-production-8293.up.railway.app"

echo "=== Checking current deployment ==="
echo ""

echo "1. Testing all endpoints:"
endpoints=("/" "/health" "/predict" "/fraud-types" "/docs")
for endpoint in "${endpoints[@]}"; do
    echo -n "$endpoint → "
    curl -s -o /dev/null -w "%{http_code}\n" "$URL$endpoint"
done

echo ""
echo "2. Checking app.py content on Railway:"
echo "If it says 'Hello World', OLD code is deployed!"
echo "If it shows 33 features, NEW code is deployed!"
