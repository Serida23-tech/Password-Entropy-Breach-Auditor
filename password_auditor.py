
import hashlib
import math
import requests

API_URL = "https://api.pwnedpasswords.com/range/"


def calculate_entropy(password):
    if not password:
        return 0

    charset = 0

    if any(c.islower() for c in password):
        charset += 26
    if any(c.isupper() for c in password):
        charset += 26
    if any(c.isdigit() for c in password):
        charset += 10
    if any(not c.isalnum() for c in password):
        charset += 33

    return len(password) * math.log2(charset) if charset else 0


def check_breach(password):
    sha1_hash = hashlib.sha1(
        password.encode("utf-8")
    ).hexdigest().upper()

    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    headers = {
        "User-Agent": "PasswordEntropyBreachAuditor/1.0",
        "Add-Padding": "true"
    }

    try:
        response = requests.get(
            API_URL + prefix,
            headers=headers,
            timeout=10
        )
        response.raise_for_status()

        for line in response.text.splitlines():
            hash_suffix, count = line.split(":")
            if hash_suffix.upper() == suffix:
                return int(count)

        return 0

    except requests.RequestException:
        return None


def assess_strength(entropy):
    if entropy < 28:
        return "Very Weak"
    elif entropy < 36:
        return "Weak"
    elif entropy < 60:
        return "Moderate"
    elif entropy < 80:
        return "Strong"
    else:
        return "Very Strong"


def main():
    password = input("Enter password to audit: ")

    if not password:
        print("Password cannot be empty.")
        return

    entropy = calculate_entropy(password)

    print("\n--- Password Audit Report ---")
    print(f"Password length: {len(password)} characters")
    print(f"Estimated entropy: {entropy:.2f} bits")
    print(f"Strength estimate: {assess_strength(entropy)}")

    count = check_breach(password)

    if count is None:
        print("Breach check failed. Check your internet connection.")
    elif count > 0:
        print(f"WARNING: Found in known breaches {count:,} times!")
        print("Recommendation: Stop using this password, Change it now!!.")
    else:
        print("Not found in the HIBP password database.")
        print("This does not guarantee the password is safe.")

    print("\nPrivacy: The full password was not sent to HIBP.")


if __name__ == "__main__":
    main()
