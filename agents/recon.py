import httpx
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import json
from sqlalchemy.ext.asyncio import AsyncSession
from models import Target, ReconData
from core.session_manager import AuthSession
import asyncio

class ReconAgent:
    def __init__(self, target: Target, session: AsyncSession, max_depth: int = 2):
        self.target = target
        self.session = session
        self.max_depth = max_depth
        self.visited_urls = set()
        self.base_url = target.url
        self.domain = urlparse(self.base_url).netloc
        self.auth_session = AuthSession(self.base_url, self.session, self.target.id)

    async def run(self):
        try:
            self.target.status = "recon_running"
            await self.session.commit()
            
            await self.crawl(self.base_url, depth=0)
            
            # Directory Fuzzing (Discover hidden paths)
            await self.fuzz_directories()
            
            self.target.status = "recon_done"
            await self.session.commit()
        except Exception as e:
            print(f"Recon failed: {e}")
            self.target.status = "failed"
            await self.session.commit()
        finally:
            await self.auth_session.close()

    async def fuzz_directories(self):
        print("Starting directory fuzzing...")
        common_paths = [
            "/admin", "/login", "/wp-admin", "/api", "/v1", "/v2", 
            "/config", "/.env", "/backup", "/dev", "/test", "/phpinfo.php",
            "/.git/config", "/docker-compose.yml", "/node_modules"
        ]
        
        for path in common_paths:
            from main import STOPPED_TARGETS
            if self.target.id in STOPPED_TARGETS:
                print(f"[RECON] Stop command received. Halting directory fuzzing.")
                break
            fuzz_url = urljoin(self.base_url, path)
            try:
                # Use a small timeout for fuzzing
                response = await self.auth_session.send_request("GET", fuzz_url, timeout=2.0)
                if response.status_code == 200:
                    print(f"[FOUND] {fuzz_url}")
                    await self.extract_data(fuzz_url, response.text)
                    # If we find a new directory, crawl it once
                    await self.crawl(fuzz_url, depth=self.max_depth) 
                elif response.status_code == 403:
                    print(f"[FORBIDDEN] {fuzz_url}")
                    await self._save_recon_data("endpoint", path, "GET", details=json.dumps({"url": fuzz_url, "notes": "Forbidden access"}))
            except Exception:
                pass

    async def crawl(self, url: str, depth: int):
        from main import STOPPED_TARGETS
        if self.target.id in STOPPED_TARGETS:
            return

        if depth > self.max_depth or url in self.visited_urls or len(self.visited_urls) > 50:
            return

        self.visited_urls.add(url)
        print(f"Crawling: {url}")

        try:
            response = await self.auth_session.send_request("GET", url)
            if response.status_code != 200:
                return

            await self.extract_data(url, response.text)
            
            # Extract links and crawl recursively
            soup = BeautifulSoup(response.text, 'html.parser')
            for a_tag in soup.find_all('a', href=True):
                next_url = urljoin(url, a_tag['href'])
                # Stay in same domain
                if urlparse(next_url).netloc == self.domain:
                    # Remove fragments
                    next_url = next_url.split('#')[0]
                    await self.crawl(next_url, depth + 1)
        except Exception as e:
            print(f"Error crawling {url}: {e}")

    async def extract_data(self, url: str, html: str):
        parsed_url = urlparse(url)
        path = parsed_url.path if parsed_url.path else "/"
        
        # 1. Store Endpoint
        await self._save_recon_data("endpoint", path, "GET", details=json.dumps({"url": url}))

        # 2. Extract Parameters from URL
        query_params = parse_qs(parsed_url.query)
        if query_params:
            for param, values in query_params.items():
                await self._save_recon_data("parameter", path, "GET", details=json.dumps({
                    "param": param,
                    "example_values": values
                }))

        # 3. Extract Forms
        soup = BeautifulSoup(html, 'html.parser')
        for form in soup.find_all('form'):
            action = form.get('action') or ''
            method = (form.get('method') or 'GET').upper()
            form_path = urljoin(url, action)
            form_parsed = urlparse(form_path)
            
            if form_parsed.netloc and form_parsed.netloc != self.domain:
                continue # Skip external forms for now
                
            inputs = []
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                name = input_tag.get('name')
                if name:
                    inputs.append({"name": name, "type": input_tag.get('type', 'text')})
            
            await self._save_recon_data("form", form_parsed.path, method, details=json.dumps({
                "action": form_path,
                "inputs": inputs
            }))

    async def _save_recon_data(self, data_type: str, path: str, method: str, details: str):
        # Deduplication Check
        from sqlalchemy import select
        result = await self.session.execute(
            select(ReconData).where(
                ReconData.target_id == self.target.id,
                ReconData.data_type == data_type,
                ReconData.path == path,
                ReconData.method == method
            )
        )
        existing = result.scalar_one_or_none()
        if existing:
            return

        new_data = ReconData(
            target_id=self.target.id,
            data_type=data_type,
            path=path,
            method=method,
            details=details
        )
        self.session.add(new_data)
        await self.session.commit()

async def start_recon(target_id: int, db: AsyncSession):
    # Fetch target
    from sqlalchemy import select
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if target:
        agent = ReconAgent(target, db)
        await agent.run()
