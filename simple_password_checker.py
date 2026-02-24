# simple_password_checker.py

import sys
import re
import math
from collections import Counter
import hashlib
import requests
import string

# ------------------------
# Scoring functions
# ------------------------
def score_password(password):
    score = 0
    length = len(password)

    # Length score
    if length >= 8:
        score += 20
    elif length >= 6:
        score += 10

    # Variety
    if re.search(r'[a-z]', password):
        score += 10
    if re.search(r'[A-Z]', password):
        score += 10
    if re.search(r'[0-9]', password):
        score += 10
    if re.search(r'[^a-zA-Z0-9]', password):
        score += 10

    # Bonus for unique characters
    score += len(set(password))

    return min(score, 100)

def pretty_print(score):
    if score < 30:
        verdict = "Very Weak"
    elif score < 50:
        verdict = "Weak"
    elif score < 70:
        verdict = "Fair"
    elif score < 90:
        verdict = "Good"
    else:
        verdict = "Strong"
    print(f"Score: {score}/100   Verdict: {verdict}")

# ------------------------
# Breach check
# ------------------------
def check_pwned(password):
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        res = requests.get(url)
    except requests.exceptions.RequestException:
        return "Error connecting to HIBP API"
    if res.status_code != 200:
        return "Error checking breach"
    hashes = (line.split(':') for line in res.text.splitlines())
    for h, count in hashes:
        if h == suffix:
            return f"Password has been seen {count} times in breaches!"
    return "Password not found in breaches."

# ------------------------
# Entropy calculation
# ------------------------
def password_entropy(password):
    pool = 0
    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(c in string.punctuation for c in password):
        pool += len(string.punctuation)
    entropy = len(password) * math.log2(pool) if pool else 0
    return round(entropy, 2)

# ------------------------
# Main Program
# ------------------------
def main():
    while True:
        pw = input("Enter password to test (or blank to exit): ").strip()
        if not pw:
            print("Exiting...")
            break

        score = score_password(pw)
        pretty_print(score)

        breach_result = check_pwned(pw)
        print("Breach Status:", breach_result)

        entropy = password_entropy(pw)
        print("Entropy:", entropy, "bits")

        print("-" * 40)

if __name__ == "__main__":
    main()