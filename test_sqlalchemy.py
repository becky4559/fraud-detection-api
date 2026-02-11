try:
    import sqlalchemy
    print(f'✅ SQLAlchemy {sqlalchemy.__version__} installed')
except ImportError as e:
    print(f'❌ Import error: {e}')
    print('\nTry: python -m pip install sqlalchemy')
