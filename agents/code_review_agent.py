import httpx
import os
import json
from sqlalchemy.ext.asyncio import AsyncSession
from models import Target, CodeReview
from urllib.parse import urljoin

class CodeReviewAgent:
    def __init__(self, target: Target, session: AsyncSession):
        self.target = target
        self.session = session
        self.client = httpx.AsyncClient(timeout=10.0, verify=False)
        base_url = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
        self.ollama_url = f"{base_url}/api/generate"

    async def run(self):
        try:
            print(f"Starting Code Disclosure Scan for {self.target.url}...")
            
            # 1. Common disclosure paths
            paths = [
                "/.git/config", "/.env", "/config.php", "/config.php.bak", 
                "/web.config", "/Dockerfile", "/index.js.map", "/package.json",
                "/app.py", "/main.py", "/settings.py"
            ]
            
            for path in paths:
                url = urljoin(self.target.url, path)
                try:
                    resp = await self.client.get(url)
                    # Check if it looks like code and not a 404 page
                    if resp.status_code == 200 and len(resp.text) > 20:
                        content = resp.text
                        # Simple check for source markers
                        if any(marker in content for marker in ["<?php", "import ", "from ", "PORT", "DB_", "AWS_"]):
                            print(f"[DISCLOSURE FOUND] {url}")
                            await self.perform_code_review(path, content)
                except:
                    pass

        except Exception as e:
            print(f"Code Review Agent failed: {e}")
        finally:
            await self.client.aclose()

    async def perform_code_review(self, file_path, content):
        print(f"Performing AI Security Code Review for {file_path}...")
        
        prompt = f"""
You are a senior security researcher. Perform a SECURITY CODE REVIEW on the following source code snippet discovered during an automated scan.
File: {file_path}

Code:
{content[:2000]} # Limit to first 2000 chars for LLM context

Analyze for:
1. Hardcoded secrets (API keys, passwords).
2. Logic flaws in authentication or authorization.
3. Insecure function calls (e.g., eval, system, unsafe SQL).
4. Information disclosure in comments.

Respond with a concise bulleted summary of findings.
"""
        try:
            # Use gemma:2b for speed
            async with httpx.AsyncClient(timeout=120.0) as ai_client:
                resp = await ai_client.post(self.ollama_url, json={
                    "model": "gemma:2b",
                    "prompt": prompt,
                    "stream": False
                })
                analysis = resp.json().get("response", "Analysis failed.") if resp.status_code == 200 else "AI Offline."
                
                # Check for existing review
                from sqlalchemy import select
                res = await self.session.execute(
                    select(CodeReview).where(
                        CodeReview.target_id == self.target.id,
                        CodeReview.file_path == file_path
                    )
                )
                if res.scalar_one_or_none():
                    return

                # Save to DB
                review = CodeReview(
                    target_id=self.target.id,
                    file_path=file_path,
                    snippet=content[:500], # Store preview
                    ai_analysis=analysis
                )
                self.session.add(review)
                await self.session.commit()
                print(f"[REVIEW COMPLETE] ID: {review.id}")
        except Exception as e:
            print(f"AI Code Review failed to connect to Ollama at {self.ollama_url}: {repr(e)}")

async def start_code_review(target_id: int, db: AsyncSession):
    from sqlalchemy import select
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if target:
        agent = CodeReviewAgent(target, db)
        await agent.run()
