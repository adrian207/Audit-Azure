"""Shared test settings. Set before the app is imported so the API key middleware sees them."""
import os

TEST_API_KEY = "test-api-key"

os.environ["API_MASTER_KEY"] = TEST_API_KEY
os.environ.setdefault("ENABLE_AUDIT_LOG", "false")
os.environ.setdefault("ENABLE_RATE_LIMITING", "false")
