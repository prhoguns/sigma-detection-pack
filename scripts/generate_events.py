"""Generate a synthetic event corpus with known true positives for every rule.

Writes data/events.jsonl (one flat JSON event per line, Windows/Sysmon/Linux field names) and
data/expected.json ({rule_id: [event ids that must match]}). Every rule gets planted positives AND
deliberate near-misses that must NOT match, so the tests catch both silent failures and over-broad rules.
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(7)
START = datetime(2026, 9, 1)
HOSTS = [f"WS{i:03d}" for i in range(1, 30)] + ["DC01", "FS01", "APP01"]
USERS = [f"user{i:02d}" for i in range(1, 40)]
events: list[dict] = []
expected: dict[str, list[int]] = {}


def emit(rule_ids: list[str] | None = None, **fields) -> int:
    eid = len(events) + 1
    ts = START + timedelta(seconds=random.randint(0, 29 * 86400))
    events.append({"id": eid, "timestamp": ts.isoformat(), **fields})
    for r in rule_ids or []:
        expected.setdefault(r, []).append(eid)
    return eid


R = {n: f"7c1f2a10-{n:04d}-4a5b-9c00-{n:012d}" for n in range(1, 12)}
R[10] = "7c1f2a10-0010-4a5b-9c00-000000000010"
R[11] = "7c1f2a10-0011-4a5b-9c00-000000000011"

# ---------- background noise ----------
for _ in range(6000):
    h, u = random.choice(HOSTS), random.choice(USERS)
    kind = random.random()
    if kind < 0.45:  # process creation
        img, cmd = random.choice(
            [
                (r"C:\Windows\System32\svchost.exe", "svchost.exe -k netsvcs"),
                (r"C:\Program Files\Google\Chrome\Application\chrome.exe", "chrome.exe --type=renderer"),
                (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell.exe -ExecutionPolicy Bypass -File C:\\scripts\\inventory.ps1"),
                (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell.exe Get-Process | Export-Csv report.csv"),
                (r"C:\Windows\System32\cmd.exe", "cmd.exe /c dir"),
                (r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE", "EXCEL.EXE budget.xlsx"),
            ]
        )
        emit(host=h, product="windows", category="process_creation", EventID=1, Image=img, CommandLine=cmd, User=u, ParentImage=r"C:\Windows\explorer.exe")
    elif kind < 0.6:  # logons
        emit(host=h, product="windows", service="security", EventID=random.choice([4624, 4624, 4624, 4625]), TargetUserName=u, LogonType=random.choice([2, 3, 10]), IpAddress=f"10.10.{random.randint(1,4)}.{random.randint(10,250)}")
    elif kind < 0.7:  # lsass access by legit callers (filtered)
        emit(host=h, product="windows", category="process_access", EventID=10, SourceImage=random.choice([r"C:\Windows\System32\svchost.exe", r"C:\Program Files\Windows Defender\MsMpEng.exe", r"C:\Windows\System32\csrss.exe"]), TargetImage=r"C:\Windows\System32\lsass.exe", GrantedAccess=random.choice(["0x1010", "0x1fffff", "0x1000"]))
    elif kind < 0.78:  # provisioning creates users (filtered)
        emit(host="DC01", product="windows", service="security", EventID=4720, SubjectUserName=random.choice(["svc-provision", "svc-hr-sync"]), TargetUserName=f"new{random.randint(100,999)}")
    elif kind < 0.84:  # benign scheduled tasks
        emit(host=h, product="windows", service="security", EventID=4698, SubjectUserName=u, TaskName=random.choice([r"\Microsoft\Windows\Defrag\ScheduledDefrag", r"\GoogleUpdateTaskMachineUA"]), TaskContent=r"<Exec><Command>C:\Program Files\Google\Update\GoogleUpdate.exe</Command></Exec>")
    elif kind < 0.9:  # benign group changes (not privileged groups)
        emit(host="DC01", product="windows", service="security", EventID=4728, SubjectUserName="svc-provision", TargetUserName=random.choice(["Finance Users", "VPN Users", "Printer Operators"]), MemberName=u)
    elif kind < 0.95:  # linux ssh
        emit(host=random.choice(["vpn01", "web01", "app01"]), product="linux", service="sshd", User=random.choice(USERS + ["root"]), SourceIp=f"10.10.{random.randint(1,4)}.{random.randint(10,250)}", Message=random.choice(["Accepted publickey for", "Failed password for"]) + f" {u} from 10.10.1.5 port 5000")
    else:  # linux sudo by humans
        emit(host="app01", product="linux", service="sudo", User=u, Message=f"{u} : TTY=pts/0 ; PWD=/home/{u} ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx")

# ---------- planted positives and near-misses ----------
PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
# 1 encoded powershell
for _ in range(5):
    emit([R[1]], host=random.choice(HOSTS), product="windows", category="process_creation", EventID=1, Image=PS, CommandLine="powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA", User="user23", ParentImage=r"C:\Windows\System32\cmd.exe")
emit([R[1]], host="WS017", product="windows", category="process_creation", EventID=1, Image=r"C:\Program Files\PowerShell\7\pwsh.exe", CommandLine="pwsh.exe -EncodedCommand ZQBjAGgAbwA=", User="user23")
emit(host="WS002", product="windows", category="process_creation", EventID=1, Image=PS, CommandLine="powershell.exe -Command Get-Encoding", User="user02")  # near miss: no ' -enc '
emit(host="WS003", product="windows", category="process_creation", EventID=1, Image=r"C:\Windows\System32\cmd.exe", CommandLine="cmd.exe /c echo -enc test", User="user03")  # near miss: not powershell

# 2 mimikatz
emit([R[2]], host="WS017", product="windows", category="process_creation", EventID=1, Image=r"C:\Users\user23\AppData\Local\Temp\mk.exe", CommandLine='mk.exe "privilege::debug" "sekurlsa::logonpasswords"', User="user23")
emit([R[2]], host="DC01", product="windows", category="process_creation", EventID=1, Image=r"C:\Windows\Temp\x.exe", CommandLine="x.exe lsadump::dcsync /user:krbtgt", User="helpdesk2")
emit(host="WS004", product="windows", category="process_creation", EventID=1, Image=PS, CommandLine="powershell.exe Get-Help about_privileges", User="user04")  # near miss

# 3 lsass access by non-system
for src in (r"C:\Users\user23\AppData\Local\Temp\mk.exe", r"C:\Users\Public\procdump.exe", r"C:\Windows\Temp\dumper.exe"):
    emit([R[3]], host="WS017", product="windows", category="process_access", EventID=10, SourceImage=src, TargetImage=r"C:\Windows\System32\lsass.exe", GrantedAccess="0x1010")
emit(host="WS005", product="windows", category="process_access", EventID=10, SourceImage=r"C:\Users\user05\tool.exe", TargetImage=r"C:\Windows\System32\lsass.exe", GrantedAccess="0x1000")  # near miss: benign access mask
emit(host="WS005", product="windows", category="process_access", EventID=10, SourceImage=r"C:\Users\user05\tool.exe", TargetImage=r"C:\Windows\System32\notepad.exe", GrantedAccess="0x1fffff")  # near miss: wrong target

# 4 privileged group
emit([R[4]], host="DC01", product="windows", service="security", EventID=4728, SubjectUserName="user23", TargetUserName="Domain Admins", MemberName="helpdesk2")
emit([R[4]], host="WS017", product="windows", service="security", EventID=4732, SubjectUserName="user23", TargetUserName="Administrators", MemberName="user23")
emit([R[4]], host="DC01", product="windows", service="security", EventID=4756, SubjectUserName="helpdesk2", TargetUserName="Enterprise Admins", MemberName="helpdesk2")
emit(host="DC01", product="windows", service="security", EventID=4729, SubjectUserName="user23", TargetUserName="Domain Admins", MemberName="olduser")  # near miss: removal event

# 5 user created by unexpected account
emit([R[5]], host="DC01", product="windows", service="security", EventID=4720, SubjectUserName="user23", TargetUserName="helpdesk2")
emit([R[5]], host="WS017", product="windows", service="security", EventID=4720, SubjectUserName="Administrator", TargetUserName="backdoor")

# 6 scheduled task from user-writable path
emit([R[6]], host="DC01", product="windows", service="security", EventID=4698, SubjectUserName="helpdesk2", TaskName=r"\Updater", TaskContent=r"<Exec><Command>C:\ProgramData\upd\svc.exe</Command></Exec>")
emit([R[6]], host="WS017", product="windows", service="security", EventID=4698, SubjectUserName="user23", TaskName=r"\OneDriveSync", TaskContent=r"<Exec><Command>C:\Users\user23\AppData\Roaming\od.exe</Command></Exec>")
emit(host="WS006", product="windows", service="security", EventID=4698, SubjectUserName="user06", TaskName=r"\Backup", TaskContent=r"<Exec><Command>C:\Program Files\Veeam\backup.exe</Command></Exec>")  # near miss

# 7 cobalt strike pipe
emit([R[7]], host="WS017", product="windows", category="pipe_created", EventID=17, PipeName=r"\msagent_4a2f", Image=r"C:\Windows\System32\rundll32.exe")
emit([R[7]], host="WS017", product="windows", category="pipe_created", EventID=18, PipeName=r"\MSSE-1337-server", Image=r"C:\Windows\System32\rundll32.exe")
emit(host="WS007", product="windows", category="pipe_created", EventID=17, PipeName=r"\mojo.7777.1.abc", Image=r"C:\Program Files\Google\Chrome\Application\chrome.exe")  # near miss: real Chrome mojo pipe, different prefix

# 8 log cleared
emit([R[8]], host="WS017", product="windows", service="security", EventID=1102, SubjectUserName="user23")
emit(host="WS008", product="windows", service="security", EventID=1100, SubjectUserName="SYSTEM")  # near miss: log service shutdown

# 9 defender disabled
emit([R[9]], host="WS017", product="windows", category="registry_set", EventID=13, TargetObject=r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware", Details="DWORD (0x00000001)", Image=r"C:\Windows\regedit.exe")
emit([R[9]], host="WS017", product="windows", category="registry_set", EventID=13, TargetObject=r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring", Details="DWORD (0x00000001)", Image=PS)
emit(host="WS009", product="windows", category="registry_set", EventID=13, TargetObject=r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware", Details="DWORD (0x00000000)", Image=r"C:\Windows\System32\gpupdate.exe")  # near miss: set back to 0

# 10 ssh root from external
emit([R[10]], host="vpn01", product="linux", service="sshd", User="root", SourceIp="185.220.101.44", Message="Accepted password for root from 185.220.101.44 port 51234 ssh2")
emit(host="vpn01", product="linux", service="sshd", User="root", SourceIp="10.10.1.5", Message="Accepted publickey for root from 10.10.1.5 port 5000 ssh2")  # near miss: internal
emit(host="vpn01", product="linux", service="sshd", User="root", SourceIp="185.220.101.44", Message="Failed password for root from 185.220.101.44 port 51230 ssh2")  # near miss: failed

# 11 service account sudo shell
emit([R[11]], host="app01", product="linux", service="sudo", User="svc-backup", Message="svc-backup : TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/bin/bash")
emit(host="app01", product="linux", service="sudo", User="svc-backup", Message="svc-backup : TTY=unknown ; PWD=/ ; USER=root ; COMMAND=/usr/bin/rsync -a /srv /backup")  # near miss

Path("data").mkdir(exist_ok=True)
with open("data/events.jsonl", "w") as fh:
    for e in events:
        fh.write(json.dumps(e) + "\n")
json.dump(expected, open("data/expected.json", "w"), indent=2)
print(f"{len(events):,} events, {sum(len(v) for v in expected.values())} planted positives across {len(expected)} rules")
