#!/usr/bin/env python3
"""
================================================
    AAKASH ALI — PYTHON SECURITY TOOLKIT
================================================
A combined cybersecurity toolkit demonstrating:
- Network reconnaissance
- Password security analysis  
- Hash identification & cracking
- Security reporting

For educational and authorised testing only.
================================================
"""

import socket
import datetime
import sys
import threading
import re
import hashlib
import random
import string
import os

# ══════════════════════════════════════════════
#  SHARED DATA
# ══════════════════════════════════════════════

COMMON_PORTS = {
    21:   ("FTP",       "HIGH   ⚠️  - Anonymous login often enabled"),
    22:   ("SSH",       "MEDIUM ⚠️  - Brute force risk if weak password"),
    23:   ("Telnet",    "CRITICAL 🔴 - Unencrypted, should be disabled"),
    25:   ("SMTP",      "MEDIUM ⚠️  - Mail relay abuse possible"),
    53:   ("DNS",       "MEDIUM ⚠️  - Zone transfer risk"),
    80:   ("HTTP",      "MEDIUM ⚠️  - Unencrypted web traffic"),
    110:  ("POP3",      "MEDIUM ⚠️  - Unencrypted email"),
    135:  ("RPC",       "HIGH   ⚠️  - Common attack vector on Windows"),
    139:  ("NetBIOS",   "HIGH   ⚠️  - SMB vulnerability risk"),
    143:  ("IMAP",      "MEDIUM ⚠️  - Unencrypted email"),
    443:  ("HTTPS",     "LOW    ✅  - Encrypted web traffic"),
    445:  ("SMB",       "CRITICAL 🔴 - EternalBlue / ransomware target"),
    1433: ("MSSQL",     "HIGH   ⚠️  - Database exposed to network"),
    3306: ("MySQL",     "HIGH   ⚠️  - Database exposed to network"),
    3389: ("RDP",       "CRITICAL 🔴 - Remote desktop, brute force risk"),
    5900: ("VNC",       "HIGH   ⚠️  - Remote access, often weak auth"),
    6379: ("Redis",     "HIGH   ⚠️  - Often runs unauthenticated"),
    8080: ("HTTP-Alt",  "MEDIUM ⚠️  - Web proxy / admin panels"),
    8443: ("HTTPS-Alt", "LOW    ✅  - Alternate HTTPS"),
    27017:("MongoDB",   "HIGH   ⚠️  - Database exposed to network"),
}

HASH_SIGNATURES = [
    {"name": "MD5",     "length": 32,  "regex": r"^[a-f0-9]{32}$",   "strength": "WEAK 🔴",     "crackable": True,  "description": "Fast, broken. Cracked in seconds with modern GPUs."},
    {"name": "SHA-1",   "length": 40,  "regex": r"^[a-f0-9]{40}$",   "strength": "WEAK 🔴",     "crackable": True,  "description": "Deprecated. Collision attacks proven."},
    {"name": "SHA-256", "length": 64,  "regex": r"^[a-f0-9]{64}$",   "strength": "MODERATE 🟡", "crackable": True,  "description": "Strong but no salt — rainbow table risk."},
    {"name": "SHA-512", "length": 128, "regex": r"^[a-f0-9]{128}$",  "strength": "MODERATE 🟡", "crackable": True,  "description": "Stronger, still no salt."},
    {"name": "bcrypt",  "length": 60,  "regex": r"^\$2[aby]?\$\d{2}\$.{53}$", "strength": "STRONG 🟢", "crackable": False, "description": "Slow by design, salted. Industry standard."},
    {"name": "NTLM",    "length": 32,  "regex": r"^[A-F0-9]{32}$",   "strength": "WEAK 🔴",     "crackable": True,  "description": "Windows hash. Cracked quickly with Hashcat."},
]

WORDLIST = [
    "password", "123456", "admin", "letmein", "welcome",
    "monkey", "dragon", "master", "hello", "shadow",
    "qwerty", "abc123", "iloveyou", "sunshine", "princess",
    "football", "charlie", "donald", "password1", "superman",
    "batman", "trustno1", "whatever", "test", "root",
    "toor", "pass", "1234", "12345", "123456789",
    "password123", "admin123", "guest", "login", "secret"
]

COMMON_PASSWORDS = [
    "123456", "password", "123456789", "12345678", "12345",
    "qwerty", "abc123", "111111", "123123", "admin",
    "letmein", "welcome", "monkey", "1234567890", "dragon"
]

# ══════════════════════════════════════════════
#  UTILITIES
# ══════════════════════════════════════════════

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def banner():
    print("=" * 60)
    print("        AAKASH ALI — PYTHON SECURITY TOOLKIT")
    print("         github.com/aakashali | Sydney, AU")
    print("=" * 60)
    print("  ⚠️  For educational and authorised testing only")
    print("=" * 60)

def divider():
    print("─" * 60)

def save_report(content, prefix="report"):
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"{prefix}_{timestamp}.txt"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"\n  ✅ Report saved: {filename}")

# ══════════════════════════════════════════════
#  MODULE 1 — NETWORK SCANNER
# ══════════════════════════════════════════════

open_ports = []
lock = threading.Lock()

def _scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.3)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            service, risk = COMMON_PORTS.get(port, ("Unknown", "UNKNOWN - Investigate manually"))
            banner_txt = _grab_banner(ip, port)
            with lock:
                open_ports.append({"port": port, "service": service, "risk": risk, "banner": banner_txt})
                print(f"  [+] Port {port:5d} OPEN — {service}")
    except:
        pass

def _grab_banner(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((ip, port))
        s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        b = s.recv(1024).decode(errors="ignore").strip()
        s.close()
        return b.split("\n")[0] if b else "No banner"
    except:
        return "No banner"

def run_network_scanner():
    global open_ports
    open_ports = []

    print("\n  ┌─────────────────────────────┐")
    print("  │   MODULE 1: NETWORK SCANNER │")
    print("  └─────────────────────────────┘\n")

    target = input("  [?] Target IP address: ").strip()
    try:
        socket.inet_aton(target)
    except:
        print("  [-] Invalid IP address.")
        return

    print("\n  Scan options:")
    print("  1 — Quick  (Top 20 ports)  ~2 sec")
    print("  2 — Standard (1-1024)      ~15 sec")
    print("  3 — Full (1-65535)         ~2 min")
    choice = input("\n  [?] Choose (1/2/3): ").strip()

    if choice == "1":
        ports = list(COMMON_PORTS.keys())
        scan_type = "Quick Scan"
    elif choice == "2":
        ports = list(range(1, 1025))
        scan_type = "Standard Scan"
    elif choice == "3":
        ports = list(range(1, 65536))
        scan_type = "Full Scan"
    else:
        ports = list(COMMON_PORTS.keys())
        scan_type = "Quick Scan"

    start = datetime.datetime.now()
    print(f"\n  [*] Scanning {target} — {scan_type}")
    divider()

    # Threaded scanning in batches
    for i in range(0, len(ports), 100):
        batch = ports[i:i+100]
        threads = [threading.Thread(target=_scan_port, args=(target, p)) for p in batch]
        for t in threads: t.start()
        for t in threads: t.join()

    duration = round((datetime.datetime.now() - start).total_seconds(), 2)
    open_ports.sort(key=lambda x: x["port"])

    # Build report
    report = []
    report.append("=" * 60)
    report.append("         NETWORK SCAN REPORT")
    report.append("=" * 60)
    report.append(f"  Target    : {target}")
    report.append(f"  Scan Type : {scan_type}")
    report.append(f"  Duration  : {duration}s")
    report.append(f"  Open Ports: {len(open_ports)}")
    report.append("=" * 60)

    if not open_ports:
        report.append("\n  ✅ No open ports found.")
    else:
        report.append("\n  FINDINGS:\n")
        for f in open_ports:
            report.append(f"  Port   : {f['port']} ({f['service']})")
            report.append(f"  Risk   : {f['risk']}")
            report.append(f"  Banner : {f['banner']}\n")

        critical = [f for f in open_ports if "CRITICAL" in f["risk"]]
        high     = [f for f in open_ports if "HIGH"     in f["risk"]]
        medium   = [f for f in open_ports if "MEDIUM"   in f["risk"]]

        report.append("─" * 60)
        report.append(f"  🔴 Critical : {len(critical)}")
        report.append(f"  ⚠️  High     : {len(high)}")
        report.append(f"  ⚠️  Medium   : {len(medium)}")

    output = "\n".join(report)
    print("\n" + output)

    if input("\n  [?] Save report? (y/n): ").lower() == "y":
        save_report(output, f"network_scan_{target}")

# ══════════════════════════════════════════════
#  MODULE 2 — PASSWORD CHECKER
# ══════════════════════════════════════════════

def run_password_checker():
    print("\n  ┌────────────────────────────────────┐")
    print("  │  MODULE 2: PASSWORD STRENGTH CHECK │")
    print("  └────────────────────────────────────┘\n")

    password = input("  [?] Enter password to analyse: ")
    if not password:
        print("  [-] No password entered.")
        return

    score = 0
    feedback = []
    suggestions = []

    if password.lower() in COMMON_PASSWORDS:
        print("\n  🔴 CRITICALLY WEAK — In top common passwords list")
        print("  This would be cracked instantly.")
        return

    # Length
    if len(password) >= 16:   score += 3; feedback.append("✅ Excellent length (16+)")
    elif len(password) >= 12: score += 2; feedback.append("✅ Good length (12+)")
    elif len(password) >= 8:  score += 1; feedback.append("⚠️  Minimum length (8+)"); suggestions.append("Use 16+ characters")
    else:                                  feedback.append("❌ Too short");             suggestions.append("Use at least 16 characters")

    # Character types
    if re.search(r'[A-Z]', password): score += 1; feedback.append("✅ Has uppercase")
    else: feedback.append("❌ No uppercase"); suggestions.append("Add uppercase letters")

    if re.search(r'[a-z]', password): score += 1; feedback.append("✅ Has lowercase")
    else: feedback.append("❌ No lowercase"); suggestions.append("Add lowercase letters")

    if re.search(r'\d', password): score += 1; feedback.append("✅ Has numbers")
    else: feedback.append("❌ No numbers"); suggestions.append("Add numbers")

    if re.search(r'[!@#$%^&*()\-_=+\[\]{}|;:,.<>?]', password): score += 2; feedback.append("✅ Has special characters")
    else: feedback.append("❌ No special characters"); suggestions.append("Add special characters (!@#$)")

    if re.search(r'(.)\1{2,}', password): score -= 1; feedback.append("⚠️  Repeated characters found")
    sequences = ["abc","123","qwe","234","345","456","567","678","789"]
    if any(s in password.lower() for s in sequences): score -= 1; feedback.append("⚠️  Sequential characters found")

    score = max(0, min(score, 10))
    if score >= 8:   rating = "STRONG 🟢"
    elif score >= 6: rating = "MODERATE 🟡"
    elif score >= 4: rating = "WEAK 🟠"
    else:            rating = "VERY WEAK 🔴"

    bar = "█" * score + "░" * (10 - score)
    print(f"\n  Score  : {score}/10  [{bar}]")
    print(f"  Rating : {rating}\n")
    for item in feedback: print(f"  {item}")
    if suggestions:
        print("\n  RECOMMENDATIONS:")
        for s in suggestions: print(f"  → {s}")

    if input("\n  [?] Generate strong password? (y/n): ").lower() == "y":
        chars = (random.choices(string.ascii_uppercase, k=3) +
                 random.choices(string.ascii_lowercase, k=5) +
                 random.choices(string.digits, k=3) +
                 random.choices("!@#$%^&*()_+-=", k=3) +
                 random.choices(string.ascii_letters, k=4))
        random.shuffle(chars)
        print(f"\n  ✅ Suggested: {''.join(chars)}")
        print("  → Store in a password manager (Bitwarden recommended)")

# ══════════════════════════════════════════════
#  MODULE 3 — HASH IDENTIFIER
# ══════════════════════════════════════════════

def run_hash_identifier():
    print("\n  ┌───────────────────────────────────┐")
    print("  │  MODULE 3: HASH IDENTIFIER & CRACK│")
    print("  └───────────────────────────────────┘")

    while True:
        print("\n  1 — Identify hash")
        print("  2 — Dictionary attack")
        print("  3 — Generate hashes from plaintext")
        print("  4 — Back to main menu")
        choice = input("\n  [?] Choose: ").strip()

        if choice == "1":
            h = input("\n  [?] Enter hash: ").strip()
            matches = [s for s in HASH_SIGNATURES if re.match(s["regex"], h, re.IGNORECASE)]
            if not matches:
                print("  [-] Hash type not recognised.")
            else:
                for m in matches:
                    print(f"\n  Algorithm  : {m['name']}")
                    print(f"  Strength   : {m['strength']}")
                    print(f"  Details    : {m['description']}")
                    print(f"  Crackable  : {'Yes ⚠️' if m['crackable'] else 'No ✅'}")

        elif choice == "2":
            h = input("\n  [?] Enter hash: ").strip()
            print("  Type: 1=MD5  2=SHA-1  3=SHA-256  4=SHA-512")
            t = {"1": "md5", "2": "sha1", "3": "sha256", "4": "sha512"}.get(input("  [?] Type: ").strip())
            if not t:
                print("  [-] Invalid choice.")
                continue
            print(f"\n  [*] Attacking with {len(WORDLIST)} words...")
            cracked = None
            for word in WORDLIST:
                if hashlib.new(t, word.encode()).hexdigest() == h.lower():
                    cracked = word
                    break
            if cracked:
                print(f"\n  ✅ CRACKED: '{cracked}'")
                print("  ⚠️  Real attackers use 14M+ word lists (rockyou.txt)")
            else:
                print("  [-] Not found in wordlist.")
                print("  → Try: hashcat -m 0 hash.txt rockyou.txt")

        elif choice == "3":
            text = input("\n  [?] Enter plaintext: ").strip()
            if text:
                print(f"\n  Hashes for '{text}':")
                for algo in ["md5", "sha1", "sha256", "sha512"]:
                    print(f"  {algo.upper():<10}: {hashlib.new(algo, text.encode()).hexdigest()}")

        elif choice == "4":
            break

# ══════════════════════════════════════════════
#  MAIN MENU
# ══════════════════════════════════════════════

def main():
    while True:
        clear()
        banner()
        print("\n  MODULES:")
        print("  1 — Network Port Scanner")
        print("  2 — Password Strength Checker")
        print("  3 — Hash Identifier & Cracker")
        print("  4 — Exit")
        print()
        divider()

        choice = input("\n  [?] Select module: ").strip()

        if choice == "1":
            run_network_scanner()
        elif choice == "2":
            run_password_checker()
        elif choice == "3":
            run_hash_identifier()
        elif choice == "4":
            print("\n  [*] Exiting. Stay secure!\n")
            sys.exit(0)
        else:
            print("  [-] Invalid choice.")

        input("\n  [Enter] Return to main menu...")

if __name__ == "__main__":
    main()