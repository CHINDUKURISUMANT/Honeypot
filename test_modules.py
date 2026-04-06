import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), 'Honeypot'))

from ml.attack_intent_classifier import AttackIntentClassifier

classifier = AttackIntentClassifier()

print("\n--- Testing Decoding ---")
payload1 = "echo 'Y2F0IC9ldGMvcGFzc3dk' | base64 -d | sh"
payload2 = r"\x72\x6d\x20\x2d\x72\x66\x20\x2f"

print("Original 1: ", payload1)
print("Decoded 1 : ", classifier._preprocess_payload(payload1))
print("Original 2: ", payload2)
print("Decoded 2 : ", classifier._preprocess_payload(payload2))

print("\n--- Testing BiLSTM Interface ---")
from ml.bilstm_model import BiLSTMInterface
try:
    lstm = BiLSTMInterface()
    mat = lstm.get_sequence_embeddings(["whoami"])
    print(f"Matrix shape: {mat.shape}, Non-zero items: {(mat != 0).sum()}")
except Exception as e:
    print(f"BiLSTM loading test failed: {e}")
