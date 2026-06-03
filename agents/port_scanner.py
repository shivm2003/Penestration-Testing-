import asyncio
import socket
from sqlalchemy.ext.asyncio import AsyncSession
from models import Target, ReconData
import json

class PortScannerAgent:
    def __init__(self, target: Target, session: AsyncSession):
        self.target = target
        self.session = session
        # Top 50 most common ports for speed in Mythos loop
        self.ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 
            1723, 3306, 3389, 5432, 5900, 8080, 8443, 9000, 9090
        ]

    async def run(self):
        try:
            print(f"Starting Port Scan for {self.target.url}...")
            # Extract hostname from URL
            from urllib.parse import urlparse
            hostname = urlparse(self.target.url).netloc
            if ":" in hostname: hostname = hostname.split(":")[0]

            open_ports = []
            
            # Run port scans in parallel batches
            tasks = [self.scan_port(hostname, port) for port in self.ports]
            results = await asyncio.gather(*tasks)
            
            for res in results:
                if res:
                    open_ports.append(res)
                    print(f"[PORT OPEN] {res['port']} ({res['service']})")
                    # Save to ReconData so Scanner can see them
                    await self._save_port_data(res)

            print(f"Port scan completed. Found {len(open_ports)} open ports.")
            
        except Exception as e:
            print(f"Port Scanner failed: {e}")

    async def scan_port(self, host, port):
        try:
            # Use asyncio to attempt connection
            conn = asyncio.open_connection(host, port)
            try:
                reader, writer = await asyncio.wait_for(conn, timeout=2.0)
                writer.close()
                await writer.wait_closed()
                
                # Attempt basic service identification
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                
                return {"port": port, "service": service, "status": "open"}
            except:
                return None
        except:
            return None

    async def _save_port_data(self, data):
        # Deduplication check
        from sqlalchemy import select
        path_str = f"Port {data['port']} ({data['service']})"
        result = await self.session.execute(
            select(ReconData).where(
                ReconData.target_id == self.target.id,
                ReconData.data_type == "port",
                ReconData.path == path_str
            )
        )
        if result.scalar_one_or_none():
            return

        new_data = ReconData(
            target_id=self.target.id,
            data_type="port",
            path=path_str,
            method="TCP",
            details=json.dumps(data)
        )
        self.session.add(new_data)
        await self.session.commit()
        print(f"[RECON SAVED] Port {data['port']} ({data['service']})")

async def start_port_scan(target_id: int, db: AsyncSession):
    from sqlalchemy import select
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if target:
        agent = PortScannerAgent(target, db)
        await agent.run()
