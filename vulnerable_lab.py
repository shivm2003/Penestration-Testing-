from fastapi import FastAPI, Form, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
import sqlite3
import json

app = FastAPI(title="VAPT Vulnerable Lab")

# Setup a simple in-memory DB for the lab
db = sqlite3.connect(":memory:", check_same_thread=False)
db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT, otp_code TEXT)")
db.execute("INSERT INTO users (username, password, email, otp_code) VALUES ('admin', 'admin123', 'admin@example.com', '123456')")
db.execute("INSERT INTO users (username, password, email, otp_code) VALUES ('user1', 'pass123', 'user1@example.com', '88776')")

@app.get("/", response_class=HTMLResponse)
async def index():
    return """
    <html>
        <head><title>Vulnerable Lab - Home</title></head>
        <body>
            <h1>Welcome to the Security Training Lab</h1>
            <p>Public page. Nothing sensitive here.</p>
            <a href="/login">Login</a> | <a href="/admin/portal">Admin Portal</a>
        </body>
    </html>
    """

@app.get("/login", response_class=HTMLResponse)
async def login_page():
    return """
    <html>
        <head><title>Login - Security Lab</title></head>
        <body>
            <h2>Auth Portal</h2>
            <form action="/api/login" method="POST">
                <label>Email: <input name="email" type="text"></label><br>
                <label>Password: <input name="password" type="password"></label><br>
                <button type="submit">Sign In</button>
            </form>
            <p style="color: grey; font-size: 0.8rem;">Debug: Database v1.0.4 - SQLITE3</p>
        </body>
    </html>
    """

@app.post("/api/login")
async def login_api(email: str = Form(None), password: str = Form(None)):
    if not email or not password:
        return JSONResponse({"status": "error", "message": "Missing credentials"}, status_code=400)
    
    # VULNERABILITY 1: SQL Injection
    query = f"SELECT * FROM users WHERE email = '{email}' AND password = '{password}'"
    try:
        cursor = db.execute(query)
        user = cursor.fetchone()
        
        if user:
            # VULNERABILITY 2: Information Leakage (returning sensitive fields)
            # VULNERABILITY 3: OTP Leaked in response
            return {
                "status": "success",
                "message": f"Welcome back, {user[1]}!",
                "user_id": user[0],
                "email": user[3],
                "verification_code": user[4], # LEAK! (5 or 6 digits)
                "session_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoyNTE2MjM5MDIyfQ" # HARDCODED JWT
            }
        else:
            return JSONResponse({"status": "error", "message": "Invalid email or password"}, status_code=401)
            
    except Exception as e:
        # VULNERABILITY 4: Verbose Error Leakage
        return JSONResponse({
            "status": "error", 
            "message": "Database Error", 
            "debug_info": str(e) # LEAK!
        }, status_code=500)

@app.get("/admin/portal")
async def admin_portal(request: Request):
    # VULNERABILITY 5: Improper Access Control (Redirect to login without auth check)
    return RedirectResponse(url="/login")

@app.get("/api/config")
async def get_config():
    # VULNERABILITY 6: Exposed Internal Config
    return {
        "db_path": "/var/lib/sqlite/lab.db",
        "internal_api_key": "SK-LAB-SECRET-998877",
        "aws_region": "us-east-1",
        "debug": True
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9000)
