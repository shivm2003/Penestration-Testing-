"""
OTP Bypass Test Integration Helper
Quick setup for adding OTP bypass testing to your FastAPI main.py
"""

# ===== ADD THIS TO main.py =====

# In the imports section, add:
# from agents.otp_bypass_agent import OTPBypassAgent

# Then add this endpoint to your FastAPI app:

@app.post("/api/targets/{target_id}/otp-bypass")
async def trigger_otp_bypass(target_id: int, background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db)):
    """
    Trigger OTP bypass testing on target.
    Tests for response manipulation, parameter pollution, client-side validation bypass, etc.
    """
    result = await db.execute(select(models.Target).where(models.Target.id == target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    from database import AsyncSessionLocal
    from agents.otp_bypass_agent import OTPBypassAgent
    
    async def bg_otp_test(tid: int):
        async with AsyncSessionLocal() as session:
            # Fetch fresh target instance in new session
            target_result = await session.execute(
                select(models.Target).where(models.Target.id == tid)
            )
            target = target_result.scalar_one_or_none()
            if target:
                agent = OTPBypassAgent(target, session)
                await agent.run()

    background_tasks.add_task(bg_otp_test, target_id)
    return {"message": "OTP bypass testing started in background"}


# ===== FRONTEND INTEGRATION =====

# Add to auth_lab.html JavaScript:

// In the auth lab test selector
const authTests = [
    { label: "Login Tester", value: "login", icon: "🔑" },
    { label: "JWT Analyzer", value: "jwt", icon: "🎫" },
    { label: "Rate Limit Tester", value: "ratelimit", icon: "⏱" },
    { label: "OTP Bypass", value: "otp", icon: "🔐" }  // ADD THIS
];

// Add to the trigger function
async function runAuthTest(testType) {
    const targetId = selectedTarget;
    
    const endpoints = {
        login: `/api/targets/${targetId}/login`,
        jwt: `/api/targets/${targetId}/jwt`,
        ratelimit: `/api/targets/${targetId}/ratelimit`,
        otp: `/api/targets/${targetId}/otp-bypass`  // ADD THIS
    };
    
    const response = await fetch(endpoints[testType], { method: "POST" });
    const data = await response.json();
    updateAuthLabLog(data.message);
}


# ===== STANDALONE CLI USAGE =====

# Run from command line:
# python otp_bypass_cli.py -u https://target.com -e /verify-otp -d "otp=123456&email=test@test.com"

# With burp proxy:
# python otp_bypass_cli.py -u https://target.com -e /2fa -d "otp=0000" -p http://127.0.0.1:8080 --insecure


# ===== DATABASE SCHEMA NOTE =====

# OTP test results are stored in AuthTestResult table:
# - target_id: Reference to target
# - endpoint: OTP endpoint URL tested
# - test_type: "OTP_Bypass" or specific test name
# - payload_used: JSON payload sent
# - response_preview: Response summary
# - vulnerability_found: Boolean flag
# - severity_level: "Critical", "High", "Medium", "Low"

