#!/usr/bin/env python3
"""
Password Strength Checker
Author: Aakash Ali
Description: Analyses password strength, checks against common passwords,
             scores it out of 10, and suggests a stronger alternative.
Usage: python3 password_checker.py
"""

import re
import random
import string

# ─────────────────────────────────────────────
# TOP 50 MOST COMMON PASSWORDS
# Real attackers use lists 10 million+ long
# This demonstrates the concept
# ─────────────────────────────────────────────
COMMON_PASSWORDS = [
    "123456", "password", "123456789", "12345678", "12345",
    "1234567", "1234567890", "qwerty", "abc123", "111111",
    "123123", "admin", "letmein", "welcome", "monkey",
    "1234", "sunshine", "princess", "password1", "iloveyou",
    "dragon", "master", "666666", "qwerty123", "1q2w3e",
    "123qwe", "zxcvbnm", "654321", "555555", "lovely",
    "7777777", "welcome1", "888888", "pass", "superman",
    "qazwsx", "michael", "football", "shadow", "batman",
    "trustno1", "hello", "charlie", "donald", "password123",
    "qwertyuiop", "whatever", "nintendo", "soccer", "hockey"
]

# ─────────────────────────────────────────────
# GENERATE A STRONG RANDOM PASSWORD
# ─────────────────────────────────────────────
def generate_strong_password(length=16):
    # Must include at least one of each character type
    chars = (
        random.choices(string.ascii_uppercase, k=3) +
        random.choices(string.ascii_lowercase, k=5) +
        random.choices(string.digits, k=3) +
        random.choices("!@#$%^&*()_+-=[]{}|;:,.<>?", k=3) +
        random.choices(string.ascii_letters + string.digits, k=length-14)
    )
    random.shuffle(chars)
    return "".join(chars)

# ─────────────────────────────────────────────
# ANALYSE PASSWORD STRENGTH
# Returns score, breakdown and suggestions
# ─────────────────────────────────────────────
def analyse_password(password):
    score = 0
    feedback = []
    suggestions = []

    # ── CHECK 1: Common password list ──
    if password.lower() in COMMON_PASSWORDS:
        return {
            "score": 0,
            "rating": "CRITICALLY WEAK 🔴",
            "feedback": ["❌ This is one of the most commonly used passwords in the world"],
            "suggestions": ["This password would be cracked instantly by any attacker"],
            "breakdown": {}
        }

    breakdown = {}

    # ── CHECK 2: Length ──
    length = len(password)
    breakdown["Length"] = f"{length} characters"
    if length >= 16:
        score += 3
        feedback.append("✅ Excellent length (16+ characters)")
    elif length >= 12:
        score += 2
        feedback.append("✅ Good length (12+ characters)")
    elif length >= 8:
        score += 1
        feedback.append("⚠️  Acceptable length (8+ characters)")
        suggestions.append("Increase to 16+ characters for stronger security")
    else:
        feedback.append("❌ Too short — minimum 8 characters recommended")
        suggestions.append("Use at least 16 characters for strong security")

    # ── CHECK 3: Uppercase letters ──
    has_upper = bool(re.search(r'[A-Z]', password))
    breakdown["Uppercase"] = "✅ Yes" if has_upper else "❌ No"
    if has_upper:
        score += 1
        feedback.append("✅ Contains uppercase letters")
    else:
        feedback.append("❌ No uppercase letters detected")
        suggestions.append("Add uppercase letters (A-Z)")

    # ── CHECK 4: Lowercase letters ──
    has_lower = bool(re.search(r'[a-z]', password))
    breakdown["Lowercase"] = "✅ Yes" if has_lower else "❌ No"
    if has_lower:
        score += 1
        feedback.append("✅ Contains lowercase letters")
    else:
        feedback.append("❌ No lowercase letters detected")
        suggestions.append("Add lowercase letters (a-z)")

    # ── CHECK 5: Numbers ──
    has_digit = bool(re.search(r'\d', password))
    breakdown["Numbers"] = "✅ Yes" if has_digit else "❌ No"
    if has_digit:
        score += 1
        feedback.append("✅ Contains numbers")
    else:
        feedback.append("❌ No numbers detected")
        suggestions.append("Add numbers (0-9)")

    # ── CHECK 6: Special characters ──
    has_special = bool(re.search(r'[!@#$%^&*()\-_=+\[\]{}|;:,.<>?/]', password))
    breakdown["Special chars"] = "✅ Yes" if has_special else "❌ No"
    if has_special:
        score += 2
        feedback.append("✅ Contains special characters")
    else:
        feedback.append("❌ No special characters detected")
        suggestions.append("Add special characters (!@#$%^&*)")

    # ── CHECK 7: Repeated characters ──
    has_repeats = bool(re.search(r'(.)\1{2,}', password))
    breakdown["Repeated chars"] = "⚠️  Yes" if has_repeats else "✅ No"
    if has_repeats:
        score -= 1
        feedback.append("⚠️  Contains repeated characters (weakens password)")
        suggestions.append("Avoid repeating characters (e.g. aaa, 111)")

    # ── CHECK 8: Sequential characters ──
    sequences = ["abc", "bcd", "cde", "def", "efg", "123", "234",
                 "345", "456", "567", "678", "789", "qwe", "wer",
                 "ert", "rty", "tyu", "yui", "uio", "iop"]
    has_sequence = any(seq in password.lower() for seq in sequences)
    breakdown["Sequential chars"] = "⚠️  Yes" if has_sequence else "✅ No"
    if has_sequence:
        score -= 1
        feedback.append("⚠️  Contains sequential characters (weakens password)")
        suggestions.append("Avoid sequences like '123' or 'abc'")

    # ── FINAL SCORE ──
    score = max(0, min(score, 10))  # Keep between 0-10

    # ── RATING ──
    if score >= 8:
        rating = "STRONG 🟢"
    elif score >= 6:
        rating = "MODERATE 🟡"
    elif score >= 4:
        rating = "WEAK 🟠"
    else:
        rating = "VERY WEAK 🔴"

    return {
        "score": score,
        "rating": rating,
        "feedback": feedback,
        "suggestions": suggestions,
        "breakdown": breakdown
    }

# ─────────────────────────────────────────────
# MAIN FUNCTION
# ─────────────────────────────────────────────
def run_checker():
    print("=" * 60)
    print("      AAKASH ALI — PASSWORD STRENGTH CHECKER")
    print("=" * 60)
    print("\nThis tool analyses password strength and security.")
    print("⚠️  For testing purposes only — never enter real passwords")
    print("    into tools you did not build yourself.\n")

    while True:
        password = input("[?] Enter password to analyse (or 'q' to quit): ")

        if password.lower() == 'q':
            print("\n[*] Exiting. Stay secure!")
            break

        if not password:
            print("[-] Please enter a password.\n")
            continue

        # Run analysis
        result = analyse_password(password)

        # Print results
        print("\n" + "=" * 60)
        print("                    ANALYSIS REPORT")
        print("=" * 60)

        # Score bar
        bar_filled = "█" * result["score"]
        bar_empty  = "░" * (10 - result["score"])
        print(f"\n  Strength Score : {result['score']}/10  [{bar_filled}{bar_empty}]")
        print(f"  Rating         : {result['rating']}")

        # Breakdown
        if result["breakdown"]:
            print("\n  BREAKDOWN:")
            for check, value in result["breakdown"].items():
                print(f"    {check:<20} {value}")

        # Feedback
        print("\n  FINDINGS:")
        for item in result["feedback"]:
            print(f"    {item}")

        # Suggestions
        if result["suggestions"]:
            print("\n  RECOMMENDATIONS:")
            for suggestion in result["suggestions"]:
                print(f"    → {suggestion}")

        # Offer strong password
        print("\n" + "-" * 60)
        generate = input("\n[?] Generate a strong password? (y/n): ").strip().lower()
        if generate == "y":
            strong = generate_strong_password()
            print(f"\n  ✅ Suggested strong password: {strong}")
            print("     → Store this in a password manager (Bitwarden, 1Password)")

        print("\n" + "=" * 60 + "\n")

# ─────────────────────────────────────────────
# RUN
# ─────────────────────────────────────────────
if __name__ == "__main__":
    run_checker()
