# OTP Bypass Testing Tools - Usage Guide

Comprehensive OTP vulnerability testing framework with two implementation options: integrated agent and standalone CLI.

---

## Overview

OTP (One-Time Password) bypass vulnerabilities commonly result from:
- **Response manipulation** - Client-side modification of success indicators
- **Client-side validation** - Missing server-side verification
- **Parameter pollution** - Injecting bypass parameters
- **Content-type switching** - Exploiting inconsistent type handling
- **Status code abuse** - Trusting HTTP status codes for validation
- **Referer manipulation** - Bypassing referer-based checks

---

## Option 1: Integrated OTP Bypass Agent (Auth Lab)

### Integration with Your Framework

The `agents/otp_bypass_agent.py` integrates directly with your pentesting pipeline:

```python
from agents.otp_bypass_agent import OTPBypassAgent
from database import AsyncSessionLocal
from sqlalchemy.ext.asyncio import AsyncSession

async def run_otp_tests(target_id: int):
    async with AsyncSessionLocal() as session:
        target = await session.get(Target, target_id)
        agent = OTPBypassAgent(target, session)
        await agent.run()
```

### Features

- **Automatic endpoint discovery** - Detects OTP endpoints from:
  - Common paths (`/verify-otp`, `/2fa/verify`, etc.)
  - Auth test results database
  - Recon data collection
  
- **Database integration** - Stores findings in `AuthTestResult` table
  
- **Async execution** - Non-blocking async/await pattern
  
- **All 6 attack vectors tested:**
  1. Response body manipulation
  2. HTTP status code manipulation
  3. Client-side validation bypass
  4. Parameter pollution
  5. Content-type switching
  6. Referer/origin manipulation

### Usage in Auth Lab Pipeline

```bash
# Add to main.py endpoints
@app.post("/api/targets/{target_id}/otp-bypass")
async def trigger_otp_bypass(target_id: int, background_tasks: BackgroundTasks):
    from database import AsyncSessionLocal
    from agents.otp_bypass_agent import OTPBypassAgent
    
    async def bg_otp_test(tid: int):
        async with AsyncSessionLocal() as session:
            target = await session.execute(
                select(Target).where(Target.id == tid)
            )
            target = target.scalar_one_or_none()
            if target:
                agent = OTPBypassAgent(target, session)
                await agent.run()
    
    background_tasks.add_task(bg_otp_test, target_id)
    return {"message": "OTP bypass testing started"}
```

### How to Use OTP Bypass in Auth Lab

1. Add the new endpoint to `main.py` or your orchestrator module exactly as shown above.
2. Ensure `agents/otp_bypass_agent.py` is present and imports correctly.
3. Trigger OTP bypass testing from the Auth Lab flow by calling `/api/targets/{target_id}/otp-bypass`.
4. Use `BackgroundTasks` so the test runs asynchronously and does not block the UI.
5. Optionally add a frontend button in `frontend/auth_lab.html` that sends a POST request to the new endpoint.

Example frontend call:

```js
async function runOtpBypass(targetId) {
  const response = await fetch(`/api/targets/${targetId}/otp-bypass`, { method: "POST" });
  const result = await response.json();
  console.log(result.message);
}
```

6. After execution, review findings in the database or log output. The agent stores results in `AuthTestResult`.
7. Use Burp Suite to validate any positive findings manually.

---

## Option 2: Standalone CLI Tool

### Installation

No additional dependencies required (uses only `requests`):

```bash
cd d:\VAPT\Development\Penestration-Testing-
python otp_bypass_cli.py --help
```

### Basic Usage

#### Simple Test
```bash
python otp_bypass_cli.py \
  -u https://example.com \
  -e /verify-otp \
  -d "otp=123456&email=user@example.com"
```

#### With Session Cookie
```bash
python otp_bypass_cli.py \
  -u https://example.com \
  -e /2fa/verify \
  -d "code=000000&phone=1234567890" \
  -c "sessionid=abc123xyz; path=/"
```

#### Through Burp Suite Proxy
```bash
python otp_bypass_cli.py \
  -u https://example.com \
  -e /otp/check \
  -d "otp=999999" \
  -p http://127.0.0.1:8080 \
  --insecure
```

### Command-Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `-u, --url` | **Required** - Base URL | `https://target.com` |
| `-e, --endpoint` | **Required** - OTP endpoint | `/verify-otp` or `verify-otp` |
| `-d, --data` | **Required** - Form payload | `otp=123456&email=test@test.com` |
| `-c, --cookie` | Session cookie | `sessionid=abc123; csrf=xyz` |
| `-p, --proxy` | Proxy URL | `http://127.0.0.1:8080` |
| `--insecure` | Skip SSL verification | (flag, no value) |

---

## Test Breakdown

### Test 1: Response Body Manipulation
Tests if the server accepts modified JSON/form responses with success indicators.

**Payloads:**
- `{"status": "success"}` / `{"verified": true}` / `{"success": 1}`
- Parameter injection: `otp=WRONG&status=success`

**Expected Bypass:** Server accepts response without server-side validation

---

### Test 2: HTTP Status Code Manipulation
Tests if validation depends only on HTTP status codes.

**Payloads:**
- Status code override headers (`X-Override-Status: 200`)
- Request with wrong OTP but status code override

**Expected Bypass:** Server trusts client-provided status codes

---

### Test 3: Client-Side Validation
Tests if OTP verification happens only on the frontend.

**Payloads:**
- Empty OTP: `otp=`
- Invalid OTP: `otp=0000` or `otp=999999`
- Missing OTP entirely

**Expected Bypass:** Server accepts requests without OTP parameter

---

### Test 4: Parameter Pollution
Tests if injecting override parameters bypasses checks.

**Payloads:**
- `verified=true`
- `skip_otp=true`
- `mfa_disabled=true`
- `validation=skip`

**Expected Bypass:** Server accepts override parameters

---

### Test 5: Content-Type Switching
Tests if switching between form-urlencoded and JSON bypasses validation.

**Payloads:**
- Send form data as `application/json`
- Include success fields in JSON: `{"verified": true}`

**Expected Bypass:** Server inconsistently validates different content types

---

### Test 6: Referer/Origin Manipulation
Tests if validation checks request origin.

**Payloads:**
- Various referer headers pointing to "trusted" paths
- Missing referer header

**Expected Bypass:** Server skips validation for certain referers

---

## Manual Validation with Burp Suite

When automated tests find potential bypasses, validate manually:

1. **Turn Interception ON**
   - Proxy → Intercept → Intercept is on

2. **Trigger OTP Request**
   - Submit wrong OTP on target website
   - Burp intercepts the request

3. **Modify Response**
   - Right-click intercepted request → "Do Intercept" → "Response"
   - Modify response body:
     ```json
     {"success": false, "message": "Invalid OTP"}
     ↓
     {"success": true, "message": "OTP Verified"}
     ```

4. **Forward Modified Response**
   - Click "Forward"
   - Observe if you're logged in or bypass succeeds

5. **Confirm Vulnerability**
   - If bypass works, it's confirmed vulnerable

---

## Interpreting Results

### Potential Vulnerability Found
```
[!!!] POTENTIAL BYPASS: Override: {'status': 'success'}
      Status: 200 | keyword 'verified'
```
- Test triggered a bypass condition
- Manual validation recommended

### No Bypass Detected
```
[OK] No bypass detected in this test
```
- Server properly validates OTP
- But always check with Burp Suite manually

---

## Real-World Testing Example

### Scenario: ACME Bank OTP Bypass

```bash
# 1. Discover login flow
python otp_bypass_cli.py \
  -u https://acmebank.local \
  -e /otp/verify \
  -d "otp=000000&user_id=1001" \
  --insecure

# 2. With authentication context
python otp_bypass_cli.py \
  -u https://acmebank.local \
  -e /2fa/submit \
  -d "code=123456&session=user_session_token" \
  -c "auth_token=eyJ...; path=/" \
  --insecure

# 3. Through proxy for live observation
python otp_bypass_cli.py \
  -u https://acmebank.local \
  -e /api/otp/validate \
  -d "otp=999999" \
  -p http://127.0.0.1:8080 \
  --insecure
```

### Expected Output
```
[*] Original response status: 403
[*] Attempting response manipulation bypasses...

  [>] Trying payload override: {'override': 'true', 'bypass': 'true'}
  [!!!] POTENTIAL BYPASS: Override: {'verified': 'true'}
        Status: 200 | keyword 'dashboard'
        
[RISK] Found 3 potential bypass(es)!

[!!!] VULNERABLE: OTP bypass detected!
```

---

## Integration with Main Pipeline

Add OTP testing to your orchestrator:

```python
# agents/orchestrator.py or main.py

async def start_mythos(target_id: int, session: AsyncSession):
    # ... other agents ...
    
    # Run OTP bypass tests
    from agents.otp_bypass_agent import OTPBypassAgent
    otp_agent = OTPBypassAgent(target, session)
    await otp_agent.run()
```

---

## Security Notes

- **Scope:** Only test on systems you have explicit permission for
- **SSL Warnings:** Disabling SSL verification is for testing only
- **Rate Limiting:** Tool respects timeouts; may trigger rate limits
- **Proxy:** Use Burp Suite for detailed inspection of modified responses
- **False Positives:** Always manually verify with Burp Suite

---

## Troubleshooting

### "Could not reach endpoint"
```
[!] Could not reach endpoint. Skipping test.
```
- Check endpoint URL is correct
- Verify target is accessible
- Try with `--insecure` flag if SSL issues

### Connection timeout
```
[!] Request failed: ConnectTimeout
```
- Increase timeout: add `--timeout 30`
- Check firewall/proxy settings
- Verify proxy URL if using `-p`

### "No OTP endpoints discovered"
```
[WARNING] No OTP endpoints discovered. Check manual entry.
```
- Run with explicit `-e` parameter
- Run Page Classifier first to populate endpoint database
- Check endpoint format: `/verify-otp` (not `verify-otp`)

---

## File Structure

```
Penestration-Testing-/
├── otp_bypass_cli.py           # Standalone CLI tool
├── agents/
│   └── otp_bypass_agent.py     # Integrated agent for Auth Lab
└── README.md                    # This file
```

---

## References

- **CWE-656:** Incorrect Ownership Assignment
- **CWE-287:** Improper Authentication
- **OWASP:** Authentication Bypass Techniques
- **Burp Suite:** Response Manipulation Guide

---
