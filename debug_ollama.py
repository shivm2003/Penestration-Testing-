import httpx
import asyncio

async def test():
    urls = ["http://127.0.0.1:11434/api/generate", "http://localhost:11434/api/generate"]
    for url in urls:
        print(f"\n--- Testing POST to {url} ---")
        try:
            # Check if model exists first
            tags_url = url.replace("/api/generate", "/api/tags")
            async with httpx.AsyncClient(timeout=10.0) as client:
                tags_resp = await client.get(tags_url)
                if tags_resp.status_code == 200:
                    models = [m['name'] for m in tags_resp.json().get('models', [])]
                    print(f"Available models: {models}")
                    if "gemma:2b" not in models and "gemma:2b:latest" not in models:
                        print("WARNING: gemma:2b not found! run 'ollama pull gemma:2b'")
                else:
                    print(f"Could not fetch tags from {tags_url}")

            # Test generation with long timeout
            print(f"Testing generation (timeout=120s)...")
            async with httpx.AsyncClient(timeout=120.0) as client:
                resp = await client.post(url, json={
                    "model": "gemma:2b",
                    "prompt": "hi",
                    "stream": False
                })
                print(f"Status Code: {resp.status_code}")
                if resp.status_code == 200:
                    print(f"Response Content: {resp.json().get('response')}")
                else:
                    print(f"Error: {resp.text}")
        except Exception as e:
            print(f"CRITICAL FAILURE for {url}: {repr(e)}")
            if "ConnectError" in str(e):
                print("HINT: Is Ollama running?")
            elif "ReadTimeout" in str(e):
                print("HINT: Inference is taking too long. Check CPU/GPU usage.")



if __name__ == "__main__":
    asyncio.run(test())
