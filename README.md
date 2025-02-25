JWT Vulnerability Checker (JWT-Spike)

Author: Sohaib Karim

Overview
The JWT Vulnerability Checker is a Python-based tool designed to analyze JSON Web Tokens (JWT) for potential security vulnerabilities. This program decodes the JWT, extracts and displays its details, and checks for various security weaknesses.

Features
Decodes JWT and displays its header, payload, and signature.
Identifies insecure algorithms such as none.
Checks for missing or weak signatures.
Detects brute-force vulnerability in HS256.
Identifies risks related to RS256 key confusion attacks.
Verifies expiration times and other critical claims.
Detects potential JWT header injection vulnerabilities.
Highlights missing security claims (iss, aud).
Alerts about insecure key storage practices.

Installation
No additional dependencies are required for this script. It runs using Python's built-in libraries.

Prerequisites
Python 3.x

Running the Script
Open a terminal or command prompt.

Run the script using:
python jwt_checker.py

Enter the JWT token when prompted.
The script will output the decoded JWT details along with any detected vulnerabilities.

Example Usage
Enter your JWT token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJleHAiOjE2NzcwMjQ4MDB9.RNk5fCnEGHyZB9KdyD1TzKZYVf3S9edP_SA7A7I5z8A

Output:
JWT Header:
{
    "alg": "HS256",
    "typ": "JWT"
}

JWT Payload:
{
    "user": "admin",
    "exp": 1677024800
}

JWT Signature: RNk5fCnEGHyZB9KdyD1TzKZYVf3S9edP_SA7A7I5z8A

Vulnerabilities:
- HS256 is vulnerable to brute-force attacks if a weak secret key is used.
- The JWT token has expired.

Security Considerations
Ensure JWTs are signed using secure algorithms (RS256, ES256).
Validate claims such as exp, iss, and aud.
Use strong secrets for HMAC-based JWTs.
Store private keys securely and never expose them in source code.
