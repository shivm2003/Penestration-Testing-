import json
from typing import Dict, List, Any, Optional
from urllib.parse import urlencode

class RequestTemplate:
    """
    Normalizes HTTP request structures and handles payload injection.
    Phase 2 of the VAPT Architecture.
    """
    def __init__(self, method: str, url: str, params: Dict[str, Any] = None, 
                 headers: Dict[str, str] = None, content_type: str = "application/x-www-form-urlencoded"):
        self.method = method.upper()
        self.url = url
        self.params = params or {}
        self.headers = headers or {}
        self.content_type = content_type or self.headers.get("Content-Type", "application/x-www-form-urlencoded")

    def get_parameter_names(self) -> List[str]:
        return list(self.params.keys())

    def build_payload(self, injections: Dict[str, Any]) -> Dict[str, Any]:
        """
        Merge base params with specific injections.
        Injections can use generic keys like 'email' or 'password' which 
        will be mapped to the correct form field names.
        """
        data = self.params.copy()
        
        # Smart mapping: if injection has 'email', map to field that looks like email
        for inj_key, inj_val in injections.items():
            if inj_key == "email":
                target_key = self._find_key(["email", "user", "login"])
                if target_key: data[target_key] = inj_val
                else: data[list(data.keys())[0] if data else inj_key] = inj_val
            elif inj_key == "password":
                target_key = self._find_key(["password", "pass", "pwd"])
                if target_key: data[target_key] = inj_val
                else: data[list(data.keys())[1] if len(data)>1 else inj_key] = inj_val
            else:
                data[inj_key] = inj_val
        return data

    def _find_key(self, keywords: List[str]) -> Optional[str]:
        for k in self.params.keys():
            k_lower = k.lower()
            if any(kw in k_lower for kw in keywords):
                return k
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "method": self.method,
            "url": self.url,
            "params": self.get_parameter_names(),
            "headers": self.headers,
            "content_type": self.content_type
        }

    @classmethod
    def from_form(cls, action_url: str, method: str, fields: List[Dict[str, Any]]):
        """Creates a template from BeautifulSoup-style form extraction."""
        params = {}
        for f in fields:
            name = f.get("name")
            if name:
                # Default empty values
                params[name] = ""
        
        headers = {}
        if method.upper() == "POST":
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            
        return cls(method=method, url=action_url, params=params, headers=headers)
