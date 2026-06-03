O#!/usr/bin/env python3
"""
Test script to verify data flow from DB -> API -> Frontend
Creates test data and checks if API returns it correctly
"""
import asyncio
import httpx
import json
from database import AsyncSessionLocal
import models

async def test_data_flow():
    print("=" * 60)
    print("TESTING DATA FLOW: DB -> API -> Frontend")
    print("=" * 60)
    
    # 1. Create test target in DB
    print("\n[1] Creating test target in database...")
    async with AsyncSessionLocal() as db:
        test_target = models.Target(url="https://example.com", status="testing")
        db.add(test_target)
        await db.commit()
        await db.refresh(test_target)
        target_id = test_target.id
        print(f"✓ Created target ID: {target_id}")
        
        # 2. Add test recon data
        print("\n[2] Adding test recon data...")
        recon_entries = [
            models.ReconData(target_id=target_id, data_type="endpoint", path="/api/users", method="GET"),
            models.ReconData(target_id=target_id, data_type="endpoint", path="/api/posts", method="POST"),
            models.ReconData(target_id=target_id, data_type="parameter", path="/search?q=test", method="GET"),
            models.ReconData(target_id=target_id, data_type="form", path="/login", method="POST"),
        ]
        for entry in recon_entries:
            db.add(entry)
        await db.commit()
        print(f"✓ Added {len(recon_entries)} recon entries")
        
        # 3. Add test vulnerability
        print("\n[3] Adding test vulnerability...")
        vuln = models.Vulnerability(
            target_id=target_id,
            recon_data_id=recon_entries[0].id,
            vuln_type="SQLi",
            cwe_id="CWE-89",
            severity="Critical",
            evidence="username' OR '1'='1",
            status="confirmed"
        )
        db.add(vuln)
        await db.commit()
        print(f"✓ Added test vulnerability")

    # 4. Test API endpoints
    print("\n[4] Testing API endpoints...")
    async with httpx.AsyncClient() as client:
        base_url = "http://127.0.0.1:8001/api"
        
        # Test GET targets
        print(f"\n  Testing: GET {base_url}/targets")
        resp = await client.get(f"{base_url}/targets")
        print(f"  Status: {resp.status_code}")
        targets = resp.json()
        print(f"  Found {len(targets)} targets")
        for t in targets:
            print(f"    - ID: {t['id']}, URL: {t['url']}, Status: {t['status']}")
        
        # Test GET report
        print(f"\n  Testing: GET {base_url}/targets/{target_id}/report")
        resp = await client.get(f"{base_url}/targets/{target_id}/report")
        print(f"  Status: {resp.status_code}")
        report = resp.json()
        print(f"  Report structure:")
        print(f"    - recon_data: {len(report.get('recon_data', []))} entries")
        print(f"    - vulnerabilities: {len(report.get('vulnerabilities', []))} entries")
        
        # Print recon data details
        if report.get('recon_data'):
            print(f"\n  Recon Data Details:")
            for recon in report['recon_data'][:3]:  # Show first 3
                print(f"    - [{recon['data_type'].upper()}] {recon['method']} {recon['path']}")
        
        # Print vulnerability details
        if report.get('vulnerabilities'):
            print(f"\n  Vulnerability Details:")
            for vuln in report['vulnerabilities'][:3]:  # Show first 3
                print(f"    - [{vuln['severity']}] {vuln['vuln_type']} ({vuln['cwe_id']})")
    
    print("\n" + "=" * 60)
    print("✓ DATA FLOW TEST COMPLETE")
    print(f"✓ Test Target ID: {target_id}")
    print(f"✓ Access dashboard: http://127.0.0.1:8001")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(test_data_flow())
