#!/usr/bin/env python3
"""
simple_password_checker.py
A small password strength checker for educational/ethical use.

How to run:
$ python simple_password_checker.py
or
$ python simple_password_checker.py "SomePassword123!"
"""

import sys
import re
import math
from collections import Counter

# a small list of very common passwords (extendable)
COMMON_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "123456789",
    "12345", "1234", "111111", "1234567", "dragon",
    "123123", "baseball", "abc123", "football", "monkey",
    "letmein", "696969", "shadow", "master", "666666",
    "qwertyuiop", "123321", "mustang", "1234567890", "michael"
}

# checks for simple sequences (like 'abcd', '1234')
def has_sequential_chars(s, seq_len=4):
    s_lower = s.lower()
    # check ascending sequences
    for i in range(len(s_lower) - seq_len + 1):
        chunk = s_lower[i:i+seq_len]
        if all(ord(chunk[j+1]) - ord(chunk[j]) == 1 for j in range(len(chunk)-1)):
            return True
    # descending
    for i in range(len(s_lower) - seq_len + 1):
        chunk = s_lower[i:i+seq_len]
        if all(ord(chunk[j]) - ord(chunk[j+1]) == 1 for j in range(len(chunk)-1)):
            return True
    return False

def score_password(pw: str) -> dict:
    """
    Return a dict with:
      - score (0..100)
      - verdict (Very Weak, Weak, Fair, Good, Strong)
      - feedback (list of suggestions)
      - details (component scores)
    """
    if not pw:
        return {"score": 0, "verdict": "Very Weak", "feedback": ["Password is empty."], "details": {}}

    length = len(pw)
    categories = {
        "lower": bool(re.search(r"[a-z]", pw)),
        "upper": bool(re.search(r"[A-Z]", pw)),
        "digit": bool(re.search(r"\d", pw)),
        "symbol": bool(re.search(r"[^\w\s]", pw)),  # not alphanumeric or underscore
    }
    unique_chars = len(set(pw))
    repeats = any(count > (length * 0.6) for count in Counter(pw).values())  # heavy repetition
    sequential = has_sequential_chars(pw)
    all_lower = pw.islower()
    all_upper = pw.isupper()

    # Base scoring
    score = 0
    details = {}

    # Length component (max 40 points)
    # using logarithmic-like scaling so benefits plateau
    length_score = min(40, 4 * length)  # 4 points per char up to 40 (i.e., 10+ chars saturate)
    details["length_score"] = length_score
    score += length_score

    # Character variety (max 30)
    variety_count = sum(categories.values())
    variety_score = {1: 0, 2: 10, 3: 20, 4: 30}[variety_count]
    details["variety_count"] = variety_count
    details["variety_score"] = variety_score
    score += variety_score

    # Uncommonness / common password penalty (max -40)
    common_penalty = 0
    lowered = pw.lower()
    if lowered in COMMON_PASSWORDS:
        common_penalty = 40
    else:
        # partial word matches (like 'password123')
        for common in COMMON_PASSWORDS:
            if common in lowered:
                common_penalty = max(common_penalty, 25)
    details["common_penalty"] = -common_penalty
    score -= common_penalty

    # repetition penalty
    repeat_penalty = 10 if repeats else 0
    details["repeat_penalty"] = -repeat_penalty
    score -= repeat_penalty

    # sequential penalty
    seq_penalty = 10 if sequential else 0
    details["seq_penalty"] = -seq_penalty
    score -= seq_penalty

    # all-lower or all-upper minor penalty
    case_penalty = 5 if (all_lower or all_upper) and length < 16 else 0
    details["case_penalty"] = -case_penalty
    score -= case_penalty

    # unique char bonus (small)
    unique_bonus = min(10, (unique_chars - 3) * 2) if unique_chars > 3 else 0
    details["unique_bonus"] = unique_bonus
    score += unique_bonus

    # clamp score
    score = max(0, min(100, int(round(score))))

    # Verdict
    if score < 20:
        verdict = "Very Weak"
    elif score < 40:
        verdict = "Weak"
    elif score < 60:
        verdict = "Fair"
    elif score < 80:
        verdict = "Good"
    else:
        verdict = "Strong"

    # Feedback generation
    feedback = []
    if length < 8:
        feedback.append("Use at least 8 characters; 12+ is better.")
    elif length < 12:
        feedback.append("Consider increasing length to 12+ characters for stronger security.")
    if categories["lower"] + categories["upper"] + categories["digit"] + categories["symbol"] < 3:
        feedback.append("Include a mix of uppercase, lowercase, digits and symbols.")
    if lowered in COMMON_PASSWORDS or any(common in lowered for common in COMMON_PASSWORDS):
        feedback.append("Avoid common passwords or obvious words/numbers.")
    if repeats:
        feedback.append("Avoid repeating the same character many times.")
    if sequential:
        feedback.append("Avoid simple sequences like 'abcd' or '1234'.")
    if unique_chars < 4:
        feedback.append("Use more unique characters.")
    if not feedback:
        feedback.append("Good password, but consider increasing length for maximum safety.")

    return {
        "score": score,
        "verdict": verdict,
        "feedback": feedback,
        "details": details
    }

def pretty_print(result: dict, pw: str = None):
    print("Password Analysis")
    print("-----------------")
    if pw is not None:
        print(f"Password: {pw}")
    print(f"Score: {result['score']}/100   Verdict: {result['verdict']}")
    print("\nSuggestions:")
    for item in result["feedback"]:
        print(" -", item)
    print("\nDetails:")
    for k, v in result["details"].items():
        print(f"  {k}: {v}")
    print()

def main():
    if len(sys.argv) >= 2:
        pwd = sys.argv[1]
        res = score_password(pwd)
        pretty_print(res, pw=pwd)
        return

    # interactive
    try:
        while True:
            pwd = input("Enter password to test (or blank to exit): ").strip()
            if not pwd:
                print("Exiting.")
                break
            res = score_password(pwd)
            pretty_print(res)
    except (KeyboardInterrupt, EOFError):
        print("\nExiting.")

if __name__ == "__main__":
    main()