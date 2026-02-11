import sys
print("Python version:", sys.version)
try:
    from app import app
    print("✅ App imports successfully")
    
    # Check endpoints
    endpoints = [route.path for route in app.routes if hasattr(route, 'path')]
    print("Endpoints found:", endpoints)
    
    print("\nHas /stats?", "/stats" in endpoints)
    print("Has /predict?", "/predict" in endpoints)
    print("Has /transactions?", "/transactions" in endpoints)
    
except Exception as e:
    print(f"❌ Error: {e}")
