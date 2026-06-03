import httpx
import json
import os
import asyncio
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from models import CWEData
from agents.utils import log_event

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")

class IntelligenceCollectorAgent:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def sync_cwe(self):
        """Synchronize common CWE weaknesses for intelligence baseline."""
        await log_event(self.session, None, "CWE_SYNC", "Starting CWE Intelligence synchronization...", "INFO")
        
        # In a real-world scenario, we might pull from MITRE's XML/JSON feed.
        # For this intelligence shift, we'll seed/update with a curated list of top CWEs.
        common_cwes = [
            {"id": "CWE-89", "name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", "desc": "The product constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component."},
            {"id": "CWE-79", "name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')", "desc": "The product does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users."},
            {"id": "CWE-352", "name": "Cross-Site Request Forgery (CSRF)", "desc": "The web application does not, or can not, sufficiently verify whether a well-formed, valid, consistent request was intentionally provided by the user who submitted the request."},
            {"id": "CWE-287", "name": "Improper Authentication", "desc": "When an actor claims to have a given identity, the software does not prove or insufficiently proves that the claim is correct."},
            {"id": "CWE-22", "name": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')", "desc": "The product uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the product does not properly neutralize special elements within the pathname that can cause the pathname to resolve to a location that is outside of the restricted directory."},
            {"id": "CWE-601", "name": "URL Redirection to Untrusted Site ('Open Redirect')", "desc": "A web application accepts a user-controlled input that specifies a link to an external site, and uses that link in a Redirect. This simplifies phishing attacks."},
            {"id": "CWE-94", "name": "Improper Control of Generation of Code ('Code Injection')", "desc": "The product constructs all or part of a code segment using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended code segment."},
            {"id": "CWE-77", "name": "Improper Neutralization of Special Elements used in a Command ('Command Injection')", "desc": "The product constructs all or part of a command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended command when it is sent to a downstream component."},
            {"id": "CWE-693", "name": "Protection Mechanism Failure", "desc": "The product does not use or incorrectly uses a protection mechanism that provides sufficient defense against an attack."},
            {"id": "CWE-284", "name": "Improper Access Control", "desc": "The software does not restrict or incorrectly restricts access to a resource from an unauthorized actor."},
            {"id": "CWE-319", "name": "Cleartext Transmission of Sensitive Information", "desc": "The product transmits sensitive information in cleartext that can be sniffed by unauthorized actors."},
            {"id": "CWE-943", "name": "Improper Neutralization of Special Elements in Data Query Logic", "desc": "The product constructs a data query using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended query logic."}
        ]

        count = 0
        for item in common_cwes:
            await self._upsert_cwe(item["id"], item["name"], item["desc"])
            count += 1
        
        await self.session.commit()
        await log_event(self.session, None, "CWE_SYNC", f"Successfully synced {count} CWE patterns.", "SUCCESS")
        return count

    async def _upsert_cwe(self, cwe_id: str, name: str, description: str):
        result = await self.session.execute(select(CWEData).where(CWEData.cwe_id == cwe_id))
        existing = result.scalar_one_or_none()
        
        if existing:
            existing.name = name
            existing.description = description
            existing.last_modified = datetime.utcnow()
        else:
            new_cwe = CWEData(
                cwe_id=cwe_id,
                name=name,
                description=description
            )
            self.session.add(new_cwe)
