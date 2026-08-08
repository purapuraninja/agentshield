"""Safe Python fixture: reads a local setting but never sends it anywhere."""
import os

mode = os.getenv("APP_MODE", "development")
print(f"running in {mode} mode")
