# Password-Entropy-Breach-Auditor
it combines password-strength mathematics, breach detection, and privacy protection using Python.
The tool will:
1. Calculate password entropy in bits to estimate its theoretical search space.
2. Estimate password strength based on entropy.
3. Check whether the password appears in known breaches using the Have I Been Pwned (HIBP) API.
4. Use k-Anonymity by sending only the first five characters of the password's SHA-1 hash.
5. Keep the full password and complete hash on your computer.
Important: Entropy is a theoretical estimate, not a guarantee of how long a password would resist cracking. Predictable passwords and common patterns can be much easier to guess than the estimate suggests.
