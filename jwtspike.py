import base64
import json
import time

ascii_banner = """
+--- basic

Author: Sohaib Karim

  ____  __    __  ______         _____ ____ ____  __  _    ___ 
 |    ||  |__|  ||      |       / ___/|    \    ||  |/ ]  /  _]
 |__  ||  |  |  ||      | _____(   \_ |  o  )  | |  ' /  /  [_ 
 __|  ||  |  |  ||_|  |_||     |\__  ||   _/|  | |    \ |    _]
/  |  ||  `  '  |  |  |  |_____|/  \ ||  |  |  | |     \|   [_ 
\  `  | \      /   |  |         \    ||  |  |  | |  .  ||     |
 \____j  \_/\_/    |__|          \___||__| |____||__|\_||_____|
"""
print(ascii_banner)

def decode_base64(data):
    """Decodes base64 encoded data, adding padding if necessary."""
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    return base64.urlsafe_b64decode(data).decode('utf-8')

def parse_jwt(token):
    """Parses a JWT token and returns its header, payload, and signature."""
    try:
        header_b64, payload_b64, signature_b64 = token.split('.')
        
        header = json.loads(decode_base64(header_b64))
        payload = json.loads(decode_base64(payload_b64))
        signature = signature_b64  # Signature remains encoded as we can't verify it without a secret
        
        return header, payload, signature
    except Exception as e:
        return None, None, None

def check_vulnerabilities(header, payload, signature):
    """Checks for common JWT vulnerabilities."""
    vulnerabilities = []
    
    alg = header.get('alg', '').upper()
    
    # Check for 'none' algorithm (alg)
    if alg == 'NONE':
        vulnerabilities.append("The JWT uses 'none' as the algorithm, which means it can be easily forged.")
    
    # Check if signature is missing or empty
    if not signature:
        vulnerabilities.append("JWT signature is missing, making it insecure.")
    
    # Check for HS256 vulnerabilities
    if alg == 'HS256':
        vulnerabilities.append("HS256 is vulnerable to brute-force attacks if a weak secret key is used.")
    
    # Check for RS256 vulnerabilities
    if alg == 'RS256':
        vulnerabilities.append("RS256 requires a proper public-private key pair. If improperly implemented, it may be vulnerable to key confusion attacks.")
    
    # Check for expiration time (exp)
    if 'exp' in payload:
        exp_time = payload['exp']
        current_time = int(time.time())
        if exp_time < current_time:
            vulnerabilities.append("The JWT token has expired.")
        else:
            vulnerabilities.append(f"JWT token is valid until {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(exp_time))} UTC.")
    else:
        vulnerabilities.append("The JWT does not have an expiration time (exp), making it vulnerable to token reuse.")
    
    # Additional JWT vulnerabilities based on PortSwigger:
    
    # Weak secrets
    if alg.startswith("HS"):
        vulnerabilities.append("HS-based algorithms rely on secret keys. If weak, they are susceptible to dictionary or brute-force attacks.")
    
    # Algorithm confusion attacks
    if alg in ['RS256', 'ES256']:
        vulnerabilities.append("RS256 and ES256 may be vulnerable to algorithm confusion attacks if misconfigured, allowing signature bypassing.")
    
    # JWT header injection
    if "kid" in header:
        vulnerabilities.append("The JWT contains a 'kid' (Key ID) field, which may be exploited for key injection attacks.")
    
    # Lack of issuer claim validation
    if "iss" not in payload:
        vulnerabilities.append("The JWT does not contain an 'iss' (issuer) claim, making it difficult to verify the token's origin.")
    
    # Lack of audience claim validation
    if "aud" not in payload:
        vulnerabilities.append("The JWT does not contain an 'aud' (audience) claim, which could allow misuse in different contexts.")
    
    # Insecure key storage
    vulnerabilities.append("Ensure private keys are stored securely and not exposed in source code or environment variables.")
    
    return vulnerabilities

def analyze_jwt(token):
    """Analyzes a JWT token and prints details and vulnerabilities."""
    header, payload, signature = parse_jwt(token)
    
    if header is None or payload is None:
        print("Invalid JWT token.")
        return
    
    print("JWT Header:")
    print(json.dumps(header, indent=4))
    print("\nJWT Payload:")
    print(json.dumps(payload, indent=4))
    print("\nJWT Signature:", signature)
    
    vulnerabilities = check_vulnerabilities(header, payload, signature)
    print("\nVulnerabilities:")
    for v in vulnerabilities:
        print(f"- {v}")

# Get token from user input
token = input("Enter your JWT token: ")
analyze_jwt(token)
