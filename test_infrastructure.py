import sys
import os
import time

sys.path.append(os.path.join(os.path.dirname(__file__), 'Honeypot'))

from core.orchestrator import Orchestrator
from behaviour.behaviour_classifier import BehaviourClassifier

print("Testing True Physical Sandboxing (Orchestrator)")
try:
    orch = Orchestrator()
    orch.contain_attacker("192.168.1.99")
except Exception as e:
    print(f"Exception (could be intentional if Docker isn't running locally): {e}")

print("\nTesting Self-Healing ML Loop (Behaviour Classifier)")
clf = BehaviourClassifier()

# Simulate a sequence that flags kill chain
events = [
    {"event_type": "HTTP_RECON", "attack_type": "BENIGN", "confidence": 0.0, "details": {"client_ip": "10.0.0.5", "payload": "GET / HTTP/1.1"}},
    {"event_type": "HTTP_ENV_FILE_ACCESS", "attack_type": "BENIGN", "confidence": 0.0, "details": {"client_ip": "10.0.0.5", "payload": "GET /.env HTTP/1.1"}},
    {"event_type": "SSH_KILL_CHAIN_LOGIN", "attack_type": "BENIGN", "confidence": 0.0, "details": {"client_ip": "10.0.0.5", "command": "whoami"}}
]

for ev in events:
    res = clf.process_event(ev)
    print(f"Event state: {res['behaviour']}")

# Check if ml_feedback.csv was created
time.sleep(2) # Give background thread a split second to write
csv_path = os.path.join(os.path.dirname(__file__), "Honeypot", "data", "ml_feedback.csv")
if os.path.exists(csv_path):
    print(f"\n✅ ml_feedback.csv successfully created!")
    with open(csv_path, 'r') as f:
        print(f.read().strip())
else:
    print(f"\n❌ ml_feedback.csv NOT FOUND!")

print("\nFinished Infrastructure & ML Loop test.")
