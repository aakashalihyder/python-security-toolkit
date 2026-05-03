#!/usr/bin/env python3
"""
Hash Identifier & Analyser
Author: Aakash Ali
Description: Identifies hash types, analyses their strength,
             attempts dictionary attack, and generates hashes.
Usage: python3 hash_identifier.py
"""

import hashlib
import re
import sys

# ─────────────────────────────────────────────
# HASH SIGNATURES
# Each hash type has a known length and charset
# ─────────────────────────────────────────────
HASH_SIGNATURES = [
    {
        "name":        "MD5",
        "length":      32,
        "regex":       r"^[a-f0-9]{32}$",
        "strength":    "WEAK 🔴",
        "crackable":   True,
        "description": "Fast, broken algorithm. Cracked in seconds with modern GPUs.",
        "used_in":     "Legacy systems, file checksums",
        "recommendation": "Never use for passwords. Use bcrypt or SHA-256 instead."
    },
    {
        "name":        "SHA-1",
        "length":      40,
        "regex":       r"^[a-f0-9]{40}$",
        "strength":    "WEAK 🔴",
        "crackable":   True,
        "description": "Deprecated since 2011. Collision attacks proven possible.",
        "used_in":     "Git commits, old SSL certificates",
        "recommendation": "Avoid for security purposes. Use SHA-256 minimum."
    },
    {
        "name":        "SHA-256",
        "length":      64,
        "regex":       r"^[a-f0-9]{64}$",
        "strength":    "MODERATE 🟡",
        "crackable":   True,
        "description": "Strong algorithm but no salt — rainbow table attacks possible.",
        "used_in":     "Bitcoin, TLS certificates, file integrity",
        "recommendation": "Good for file integrity. For passwords, use bcrypt with salt."
    },
    {
        "name":        "SHA-512",
        "length":      128,
        "regex":       r"^[a-f0-9]{128}$",
        "strength":    "MODERATE 🟡",
        "crackable":   True,
        "description": "Stronger than SHA-256 but still no salt.",
        "used_in":     "Linux password storage (with salt), certificates",
        "recommendation": "Use with salt for passwords. Argon2 is better for passwords."
    },
    {
        "name":        "bcrypt",
        "length":      60,
        "regex":       r"^\$2[aby]?\$\d{2}\$.{53}$",
        "strength":    "STRONG 🟢",
        "crackable":   False,
        "description": "Slow by design, includes salt. Industry standard for passwords.",
        "used_in":     "Web application password storage",
        "recommendation": "Good choice. Keep cost factor at 12+ for modern systems."
    },
    {
        "name":        "NTLM",
        "length":      32,
        "regex":       r"^[A-F0-9]{32}$",
        "strength":    "WEAK 🔴",
        "crackable":   True,
        "description": "Windows password hash. Cracked quickly with Hashcat.",
        "used_in":     "Windows Active Directory authentication",
        "recommendation": "Enable NTLMv2 minimum. Use Kerberos where possible."
    },
    {
        "name":        "SHA-384",
        "length":      96,
        "regex":       r"^[a-f0-9]{96}$",
        "strength":    "MODERATE 🟡",
        "crackable":   True,
        "description": "Part of SHA-2 family. Stronger but still no built-in salt.",
        "used_in":     "TLS certificates, digital signatures",
        "recommendation": "Fine for non-password use. Add salt for password hashing."
    },
    {
        "name":        "MD4",
        "length":      32,
        "regex":       r"^[a-f0-9]{32}$",
        "strength":    "CRITICAL 🔴",
        "crackable":   True,
        "description": "Severely broken. Predecessor to MD5.",
        "used_in":     "Legacy Windows systems (NTLM basis)",
        "recommendation": "Never use. Replace immediately if found in any system."
    },
]

# ─────────────────────────────────────────────
# COMMON WORDLIST FOR DICTIONARY ATTACK
# Real tools use millions of words
# This demonstrates the concept
# ─────────────────────────────────────────────
WORDLIST = [
    "password", "123456", "admin", "letmein", "welcome",
    "monkey", "dragon", "master", "hello", "shadow",
    "qwerty", "abc123", "iloveyou", "sunshine", "princess",
    "football", "charlie", "donald", "password1", "superman",
    "batman", "trustno1", "whatever", "test", "root",
    "toor", "pass", "1234", "12345", "123456789",
    "password123", "admin123", "guest", "login", "secret",
    "changeme", "default", "system", "user", "manager"
]

# ─────────────────────────────────────────────
# IDENTIFY HASH TYPE
# ─────────────────────────────────────────────
def identify_hash(hash_string):
    matches = []
    hash_string = hash_string.strip()

    for sig in HASH_SIGNATURES:
        if re.match(sig["regex"], hash_string, re.IGNORECASE):
            matches.append(sig)

    return matches

# ─────────────────────────────────────────────
# DICTIONARY ATTACK
# Hashes each word and compares to target
# ─────────────────────────────────────────────
def dictionary_attack(hash_string, hash_type):
    hash_string = hash_string.strip().lower()
    print(f"\n[*] Running dictionary attack ({len(WORDLIST)} words)...")

    # Map hash type to hashlib function
    hash_functions = {
        "MD5":    hashlib.md5,
        "SHA-1":  hashlib.sha1,
        "SHA-256":hashlib.sha256,
        "SHA-512":hashlib.sha512,
        "SHA-384":hashlib.sha384,
    }

    if hash_type not in hash_functions:
        print(f"[-] Dictionary attack not supported for {hash_type}")
        return None

    hash_func = hash_functions[hash_type]

    for word in WORDLIST:
        # Hash the word and compare
        attempt = hash_func(word.encode()).hexdigest()
        if attempt == hash_string:
            return word

    return None

# ─────────────────────────────────────────────
# GENERATE HASH FROM PLAINTEXT
# ─────────────────────────────────────────────
def generate_hashes(plaintext):
    print(f"\n{'='*60}")
    print(f"  HASHES FOR: '{plaintext}'")
    print(f"{'='*60}")

    algorithms = {
        "MD5":     hashlib.md5,
        "SHA-1":   hashlib.sha1,
        "SHA-256": hashlib.sha256,
        "SHA-512": hashlib.sha512,
        "SHA-384": hashlib.sha384,
    }

    for name, func in algorithms.items():
        h = func(plaintext.encode()).hexdigest()
        print(f"  {name:<10} : {h}")

    print(f"\n  ⚠️  Note: These are unsalted hashes.")
    print(f"  Real password storage should always use salted hashing.")

# ─────────────────────────────────────────────
# MAIN MENU
# ─────────────────────────────────────────────
def run_tool():
    print("=" * 60)
    print("       AAKASH ALI — HASH IDENTIFIER & ANALYSER")
    print("=" * 60)
    print("\n  Understanding hashes is fundamental to cybersecurity.")
    print("  This tool demonstrates hash identification, analysis,")
    print("  and basic dictionary attack concepts.\n")

    while True:
        print("─" * 60)
        print("  OPTIONS:")
        print("  1 — Identify & analyse a hash")
        print("  2 — Run dictionary attack on a hash")
        print("  3 — Generate hashes from plaintext")
        print("  4 — Exit")
        print("─" * 60)

        choice = input("\n[?] Choose option: ").strip()

        # ── OPTION 1: Identify hash ──
        if choice == "1":
            hash_input = input("\n[?] Enter hash to identify: ").strip()

            if not hash_input:
                print("[-] No hash entered.")
                continue

            matches = identify_hash(hash_input)

            print(f"\n{'='*60}")
            print(f"  HASH ANALYSIS")
            print(f"{'='*60}")
            print(f"  Hash     : {hash_input[:50]}{'...' if len(hash_input) > 50 else ''}")
            print(f"  Length   : {len(hash_input)} characters")

            if not matches:
                print(f"\n  [-] Hash type not recognised.")
                print(f"  → Could be a custom hash, salted hash, or encoding")
                print(f"  → Try CyberChef or hash-identifier tool for more options")
            else:
                print(f"\n  POSSIBLE MATCHES: {len(matches)} found\n")
                for match in matches:
                    print(f"  Algorithm    : {match['name']}")
                    print(f"  Strength     : {match['strength']}")
                    print(f"  Description  : {match['description']}")
                    print(f"  Common use   : {match['used_in']}")
                    print(f"  Crackable    : {'Yes ⚠️' if match['crackable'] else 'No ✅'}")
                    print(f"  Recommendation: {match['recommendation']}")
                    print()

        # ── OPTION 2: Dictionary attack ──
        elif choice == "2":
            hash_input = input("\n[?] Enter hash to crack: ").strip()
            print("\n[?] Select hash type:")
            print("    1 — MD5")
            print("    2 — SHA-1")
            print("    3 — SHA-256")
            print("    4 — SHA-512")

            type_choice = input("\n[?] Choose (1/2/3/4): ").strip()
            type_map = {"1": "MD5", "2": "SHA-1", "3": "SHA-256", "4": "SHA-512"}

            if type_choice not in type_map:
                print("[-] Invalid choice.")
                continue

            hash_type = type_map[type_choice]
            result = dictionary_attack(hash_input, hash_type)

            print(f"\n{'='*60}")
            print(f"  DICTIONARY ATTACK RESULTS")
            print(f"{'='*60}")
            if result:
                print(f"\n  ✅ CRACKED!")
                print(f"  Hash      : {hash_input}")
                print(f"  Plaintext : {result}")
                print(f"\n  ⚠️  This password was found in a basic wordlist.")
                print(f"  Real attackers use lists with 10 billion+ entries.")
            else:
                print(f"\n  [-] Not found in wordlist.")
                print(f"  → Password may be stronger or not in common wordlists")
                print(f"  → Real tools: Hashcat with rockyou.txt (14M passwords)")
                print(f"  → Try: hashcat -m 0 hash.txt rockyou.txt")

        # ── OPTION 3: Generate hashes ──
        elif choice == "3":
            plaintext = input("\n[?] Enter text to hash: ").strip()
            if plaintext:
                generate_hashes(plaintext)
            else:
                print("[-] No text entered.")

        # ── OPTION 4: Exit ──
        elif choice == "4":
            print("\n[*] Exiting. Stay secure!")
            break

        else:
            print("[-] Invalid option. Please choose 1-4.")

# ─────────────────────────────────────────────
# RUN
# ─────────────────────────────────────────────
if __name__ == "__main__":
    run_tool()