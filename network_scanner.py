#!/usr/bin/env python3
"""
Network Port Scanner
Author: Aakash Ali
Description: Scans a target IP for open ports, identifies services,
             and generates a basic security report.
Usage: python3 network_scanner.py
"""

import socket
import datetime
import sys
import threading

# ─────────────────────────────────────────────
# COMMON PORTS & THEIR SERVICES
# ─────────────────────────────────────────────
COMMON_PORTS = {
    21:   ("FTP",        "HIGH   ⚠️  - Anonymous login often enabled"),
    22:   ("SSH",        "MEDIUM ⚠️  - Brute force risk if weak password"),
    23:   ("Telnet",     "CRITICAL 🔴 - Unencrypted, should be disabled"),
    25:   ("SMTP",       "MEDIUM ⚠️  - Mail relay abuse possible"),
    53:   ("DNS",        "MEDIUM ⚠️  - Zone transfer risk"),
    80:   ("HTTP",       "MEDIUM ⚠️  - Unencrypted web traffic"),
    110:  ("POP3",       "MEDIUM ⚠️  - Unencrypted email"),
    135:  ("RPC",        "HIGH   ⚠️  - Common attack vector on Windows"),
    139:  ("NetBIOS",    "HIGH   ⚠️  - SMB vulnerability risk"),
    143:  ("IMAP",       "MEDIUM ⚠️  - Unencrypted email"),
    443:  ("HTTPS",      "LOW    ✅  - Encrypted web traffic"),
    445:  ("SMB",        "CRITICAL 🔴 - EternalBlue / ransomware target"),
    1433: ("MSSQL",      "HIGH   ⚠️  - Database exposed to network"),
    3306: ("MySQL",      "HIGH   ⚠️  - Database exposed to network"),
    3389: ("RDP",        "CRITICAL 🔴 - Remote desktop, brute force risk"),
    5900: ("VNC",        "HIGH   ⚠️  - Remote access, often weak auth"),
    6379: ("Redis",      "HIGH   ⚠️  - Often runs unauthenticated"),
    8080: ("HTTP-Alt",   "MEDIUM ⚠️  - Web proxy / admin panels"),
    8443: ("HTTPS-Alt",  "LOW    ✅  - Alternate HTTPS"),
    27017:("MongoDB",    "HIGH   ⚠️  - Database exposed to network"),
}

# ─────────────────────────────────────────────
# SHARED RESULTS LIST + LOCK
# Threading needs a lock to safely write results
# ─────────────────────────────────────────────
open_ports = []
lock = threading.Lock()

# ─────────────────────────────────────────────
# SCAN A SINGLE PORT (threaded)
# ─────────────────────────────────────────────
def scan_port(ip, port, timeout=0.3):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()

        if result == 0:
            # Get service info
            if port in COMMON_PORTS:
                service, risk = COMMON_PORTS[port]
            else:
                service = "Unknown"
                risk = "UNKNOWN - Investigate manually"

            # Grab banner
            banner = grab_banner(ip, port)

            # Safely add to shared results list
            with lock:
                open_ports.append({
                    "port":    port,
                    "service": service,
                    "risk":    risk,
                    "banner":  banner
                })
                print(f"[+] Port {port:5d} OPEN — {service}")

    except socket.error:
        pass

# ─────────────────────────────────────────────
# GRAB SERVICE BANNER
# ─────────────────────────────────────────────
def grab_banner(ip, port, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()
        return banner.split("\n")[0] if banner else "No banner"
    except:
        return "No banner retrieved"

# ─────────────────────────────────────────────
# VALIDATE IP ADDRESS
# ─────────────────────────────────────────────
def validate_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

# ─────────────────────────────────────────────
# MAIN SCANNER
# ─────────────────────────────────────────────
def run_scanner():
    global open_ports
    open_ports = []  # Reset results for each run

    print("=" * 60)
    print("       AAKASH ALI — PYTHON NETWORK PORT SCANNER")
    print("         ⚡ Threaded — Fast Scanning Edition")
    print("=" * 60)

    # Get target IP
    target = input("\n[?] Enter target IP address: ").strip()

    if not validate_ip(target):
        print("[-] Invalid IP address. Please try again.")
        sys.exit(1)

    # Port range selection
    print("\n[?] Port range options:")
    print("    1 — Quick scan  (Top 20 common ports) ~2 seconds")
    print("    2 — Standard    (1–1024)              ~15 seconds")
    print("    3 — Full scan   (1–65535)             ~2 minutes")
    choice = input("\n[?] Choose option (1/2/3): ").strip()

    if choice == "1":
        ports = list(COMMON_PORTS.keys())
        scan_type = "Quick Scan (Top 20 Common Ports)"
    elif choice == "2":
        ports = list(range(1, 1025))
        scan_type = "Standard Scan (Ports 1-1024)"
    elif choice == "3":
        ports = list(range(1, 65536))
        scan_type = "Full Scan (Ports 1-65535)"
    else:
        print("[-] Invalid choice. Running quick scan.")
        ports = list(COMMON_PORTS.keys())
        scan_type = "Quick Scan (Top 20 Common Ports)"

    start_time = datetime.datetime.now()

    print(f"\n[*] Target    : {target}")
    print(f"[*] Scan type : {scan_type}")
    print(f"[*] Threads   : {min(100, len(ports))}")
    print(f"[*] Started   : {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 60)

    # ─────────────────────────────────────────
    # THREADING — scan ports in batches of 100
    # Much faster than scanning one at a time
    # ─────────────────────────────────────────
    threads = []
    batch_size = 100  # Run 100 threads at once

    for i in range(0, len(ports), batch_size):
        batch = ports[i:i + batch_size]

        # Create a thread for each port in batch
        for port in batch:
            t = threading.Thread(target=scan_port, args=(target, port))
            threads.append(t)
            t.start()

        # Wait for this batch to finish before next batch
        for t in threads:
            t.join()
        threads = []

    end_time = datetime.datetime.now()
    duration = round((end_time - start_time).total_seconds(), 2)

    # Sort results by port number
    open_ports.sort(key=lambda x: x["port"])

    # ─────────────────────────────────────────
    # PRINT REPORT
    # ─────────────────────────────────────────
    print("\n" + "=" * 60)
    print("                  SECURITY REPORT")
    print("=" * 60)
    print(f"  Target IP   : {target}")
    print(f"  Scan Type   : {scan_type}")
    print(f"  Scan Time   : {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Duration    : {duration} seconds ⚡")
    print(f"  Open Ports  : {len(open_ports)} found")
    print("=" * 60)

    if not open_ports:
        print("\n[✅] No open ports found. Target appears well secured.")
    else:
        print("\n FINDINGS:\n")
        for finding in open_ports:
            print(f"  Port  : {finding['port']} ({finding['service']})")
            print(f"  Risk  : {finding['risk']}")
            print(f"  Banner: {finding['banner']}")
            print()

        critical = [f for f in open_ports if "CRITICAL" in f["risk"]]
        high     = [f for f in open_ports if "HIGH" in f["risk"]]
        medium   = [f for f in open_ports if "MEDIUM" in f["risk"]]

        print("-" * 60)
        print(" RISK SUMMARY:")
        print(f"  🔴 Critical : {len(critical)}")
        print(f"  ⚠️  High     : {len(high)}")
        print(f"  ⚠️  Medium   : {len(medium)}")
        print("-" * 60)

        if critical:
            print("\n[!] CRITICAL PORTS DETECTED — Immediate action recommended:")
            for f in critical:
                print(f"    → Port {f['port']} ({f['service']}) — {f['risk']}")

    print("\n[*] Scan complete.")
    print("=" * 60)

    # Save report
    save = input("\n[?] Save report to file? (y/n): ").strip().lower()
    if save == "y":
        filename = f"scan_report_{target}_{start_time.strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, "w", encoding="utf-8") as f:
            f.write("NETWORK SECURITY SCAN REPORT\n")
            f.write("=" * 60 + "\n")
            f.write(f"Target    : {target}\n")
            f.write(f"Scan Type : {scan_type}\n")
            f.write(f"Date/Time : {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Duration  : {duration} seconds\n")
            f.write(f"Open Ports: {len(open_ports)}\n\n")
            for finding in open_ports:
                f.write(f"Port   : {finding['port']} ({finding['service']})\n")
                f.write(f"Risk   : {finding['risk']}\n")
                f.write(f"Banner : {finding['banner']}\n\n")
        print(f"[✅] Report saved as: {filename}")

if __name__ == "__main__":
    run_scanner()