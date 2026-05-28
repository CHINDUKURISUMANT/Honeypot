import os
import requests

CORE_API = os.environ.get("CORE_API", "http://honeypot_core:5001")

def api_get(path, timeout=5):
    try:
        r = requests.get(f"{CORE_API}{path}", timeout=timeout, headers={"Host": "localhost:5001"})
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}

def api_post(path, body=None, timeout=5):
    try:
        r = requests.post(f"{CORE_API}{path}", json=body, timeout=timeout, headers={"Host": "localhost:5001"})
        return r.status_code == 200
    except Exception:
        return False
