import re
import base64

def _preprocess_payload(text: str) -> str:
    # 1. SQL comments (/**/)
    text = text.replace("/**/", " ")
    
    # 2. Try hex decoding (\x72\x6d...)
    if r"\x" in text:
        try:
            hex_str = text.replace(r"\x", "")
            decoded_hex = bytes.fromhex(hex_str).decode('utf-8', errors='ignore')
            if len(decoded_hex) >= len(text) * 0.3:
                text = decoded_hex
        except Exception:
            pass

    # 3. Try finding Base64 strings
    b64_matches = re.findall(r"(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?", text)
    print("b64 matched: ", b64_matches)
    for b64 in b64_matches:
        try:
            decoded = base64.b64decode(b64).decode('utf-8')
            if decoded.isprintable():
                text = text.replace(b64, decoded)
        except Exception:
            continue

    return text

print(_preprocess_payload("echo 'Y2F0IC9ldGMvcGFzc3dk' | base64 -d | sh"))
print(_preprocess_payload(r"\x72\x6d\x20\x2d\x72\x66\x20\x2f"))
