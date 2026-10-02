import os
os.environ.setdefault("BSA_ENV","test")
os.environ.setdefault("BSA_ADMIN_EMAIL","admin@besafe.local")
os.environ.setdefault("BSA_ADMIN_PASSWORD","Bsa-Test-Only-2026!")
os.environ.setdefault("BSA_JWT_SECRET","test-only-jwt-secret-32-characters-minimum")
os.environ.setdefault("BSA_AUTH_DB","/tmp/bsa_test_auth.db")
os.environ.setdefault("BSA_DEMO_DATA","1")
