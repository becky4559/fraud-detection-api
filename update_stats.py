# Update the stats endpoint
import re

with open('app.py', 'r') as f:
    content = f.read()

# Find and replace the stats endpoint
new_stats_code = '''@app.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    total = db.query(database.Transaction).count()
    high_risk = db.query(database.Transaction).filter(database.Transaction.risk_level == "HIGH").count()
    medium_risk = db.query(database.Transaction).filter(database.Transaction.risk_level == "MEDIUM").count()
    low_risk = db.query(database.Transaction).filter(database.Transaction.risk_level == "LOW").count()
    fraud_types = db.query(database.FraudType).count()
    
    # Calculate percentages
    if total > 0:
        high_percent = (high_risk / total) * 100
        medium_percent = (medium_risk / total) * 100
        low_percent = (low_risk / total) * 100
    else:
        high_percent = medium_percent = low_percent = 0
    
    return {
        "database_summary": {
            "total_transactions": total,
            "transactions_by_risk": {
                "high_risk": high_risk,
                "medium_risk": medium_risk,
                "low_risk": low_risk
            },
            "risk_percentages": {
                "high_risk": round(high_percent, 1),
                "medium_risk": round(medium_percent, 1),
                "low_risk": round(low_percent, 1)
            },
            "fraud_types_configured": fraud_types
        },
        "timestamp": datetime.now().isoformat()
    }'''

# Replace the old stats endpoint
pattern = r'@app\.get\("/stats"\).*?return \{.*?\}'
content = re.sub(pattern, new_stats_code, content, flags=re.DOTALL)

with open('app.py', 'w') as f:
    f.write(content)

print("✅ Updated stats endpoint")
