# 🔐 Python Security Toolkit

**Author:** Aakash Ali  
**LinkedIn:** https://www.linkedin.com/in/aakashali/
**Location:** Sydney, Australia

---


![Code Quality Check](https://github.com/aakashalihyder/python-security-toolkit/actions/workflows/python-check.yml/badge.svg)


---

## 📋 Overview

A collection of Python-based cybersecurity tools built to demonstrate practical security skills including network reconnaissance, password analysis, hash identification, and dictionary attacks. All tools are built using Python standard libraries only — no external dependencies required.

> ⚠️ **Legal Disclaimer:** These tools are intended for **educational purposes and authorised testing only**. Only use on systems you own or have explicit written permission to test. Unauthorised use may be illegal under Australian and international law.

---

## 🛠️ Tools Included

### 1. `network_scanner.py` — Network Port Scanner

A multithreaded network scanner that performs fast port scanning and service enumeration.

**Features:**

- Scans target IP for open ports across 3 scan modes (Quick / Standard / Full)
- Identifies running services on each open port
- Grabs service banners for fingerprinting
- Rates each finding by risk level (Critical / High / Medium / Low)
- Flags commonly exploited ports (SMB, RDP, Telnet, FTP)
- Multithreaded scanning — 100 ports simultaneously for speed
- Saves formatted security report to file

**Skills demonstrated:**

- TCP/IP networking fundamentals
- Multithreading with Python `threading` module
- Network reconnaissance methodology
- Security risk assessment and reporting

---

### 2. `password_checker.py` — Password Strength Checker

Analyses password strength across multiple security criteria and generates secure alternatives.

**Features:**

- Checks against top 50 most common passwords (instant fail)
- Analyses length, character diversity, sequences and repetition
- Scores password out of 10 with visual strength bar
- Provides specific improvement recommendations
- Generates cryptographically random strong passwords

**Skills demonstrated:**

- Authentication security principles
- Regex pattern matching
- Brute force and dictionary attack awareness
- Secure password generation

---

### 3. `hash_identifier.py` — Hash Identifier & Analyser

Identifies cryptographic hash types, analyses their security strength, and simulates dictionary attacks.

**Features:**

- Identifies MD5, SHA-1, SHA-256, SHA-512, bcrypt, NTLM hashes
- Explains strength and known vulnerabilities for each algorithm
- Simulates dictionary attack against common wordlist
- Generates hashes from plaintext for comparison
- References real-world tools (Hashcat, rockyou.txt)

**Skills demonstrated:**

- Cryptography and hashing fundamentals
- Digital Forensics & Incident Response (DFIR) concepts
- Dictionary attack methodology
- Understanding of NTLM, bcrypt and password storage security

---

### 4. `security_toolkit.py` — Combined Security Toolkit ⭐

A unified menu-driven interface combining all three tools into one professional application.

**Features:**

- Clean terminal UI with module selection menu
- Full network scanner with threaded scanning
- Password strength checker with score and recommendations
- Hash identifier with dictionary attack and hash generation
- Consistent report saving across all modules
- Cross-platform (Windows / Linux / macOS)

**Skills demonstrated:**

- Software architecture and modular design
- User experience in CLI tools
- Integration of multiple security functions
- Professional tool development

---

## ⚙️ Requirements

- Python 3.x
- No external libraries required
- Uses only built-in modules: `socket`, `threading`, `hashlib`, `re`, `datetime`, `random`, `string`, `os`, `sys`

---

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/aakashali/python-security-toolkit
cd python-security-toolkit

# Run the combined toolkit (recommended)
python3 security_toolkit.py

# Or run individual tools
python3 network_scanner.py
python3 password_checker.py
python3 hash_identifier.py
```

---

## 📸 Example Output

### Network Scanner

```
============================================================
       AAKASH ALI — PYTHON NETWORK PORT SCANNER
         Threaded — Fast Scanning Edition
============================================================

[?] Enter target IP address: 192.168.1.1
[*] Scanning 192.168.1.1 — Quick Scan
[+] Port    22 OPEN — SSH
[+] Port    80 OPEN — HTTP
[+] Port   443 OPEN — HTTPS

  Duration    : 1.8 seconds
  Open Ports  : 3 found
  Critical    : 0  |  High : 0  |  Medium : 2
```

### Password Checker

```
  Score  : 8/10  [████████░░]
  Rating : STRONG

  Good length (16+)
  Has uppercase, lowercase, numbers, special characters
```

### Hash Identifier

```
  Algorithm  : MD5
  Strength   : WEAK
  Crackable  : Yes

  [*] Running dictionary attack...
  CRACKED: 'password'
```

---

## 🗺️ Concepts Covered

| Concept                               | Tool             |
| ------------------------------------- | ---------------- |
| TCP/IP port scanning                  | Network Scanner  |
| Service enumeration & banner grabbing | Network Scanner  |
| Multithreading for performance        | Network Scanner  |
| Authentication security               | Password Checker |
| Brute force awareness                 | Password Checker |
| Cryptographic hash algorithms         | Hash Identifier  |
| Dictionary attack simulation          | Hash Identifier  |
| NTLM / bcrypt / MD5 security          | Hash Identifier  |
| DFIR fundamentals                     | Hash Identifier  |
| CLI tool architecture                 | Security Toolkit |

---

## 🗺️ Roadmap

- [x] Network port scanner with threading
- [x] Password strength checker
- [x] Hash identifier and dictionary attack
- [x] Combined security toolkit
- [ ] Subdomain enumerator
- [ ] CVE lookup tool (via NVD API)
- [ ] Automated vulnerability report generator

---

## 📚 References & Further Learning

- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [MITRE ATT&CK — Discovery Techniques](https://attack.mitre.org/tactics/TA0007/)
- [Hashcat Documentation](https://hashcat.net/wiki/)
- [NIST Password Guidelines (SP 800-63B)](https://pages.nist.gov/800-63-3/sp800-63b.html)

---



## 📬 Contact

**Aakash Ali** — Cybersecurity Analyst
https://www.linkedin.com/in/aakashali/  
Sydney, Australia
