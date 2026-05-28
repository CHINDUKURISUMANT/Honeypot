import json
from collections import deque
from pathlib import Path

LOG_FILE = Path("/app/data/logs/events.log")

def load_events(max_events=1000):
    if not LOG_FILE.exists():
        return []
    
    events = []
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            lines = deque(f, maxlen=max_events)
            
        for line in lines:
            try:
                events.append(json.loads(line))
            except Exception:
                continue
    except Exception:
        pass
        
    return events
