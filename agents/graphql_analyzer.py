import json
from typing import List, Any
from core.base_agent import ShivamAgent, Finding, RiskLevel

class GraphQLAnalyzerAgent(ShivamAgent):
    name = "graphql_analyzer"
    phase = "weaponization"
    
    INTROSPECTION_QUERY = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          kind
          name
          description
          fields {
            name
            description
            args {
              name
              description
              type { ...TypeRef }
              defaultValue
            }
            type { ...TypeRef }
            isDeprecated
            deprecationReason
          }
        }
      }
    }
    fragment TypeRef on __Type {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
          }
        }
      }
    }
    """

    async def execute(self, target: Any, session: Any = None) -> List[Finding]:
        findings = []
        url = getattr(target, 'url', str(target))
        
        # Common GraphQL endpoints
        endpoints = ["/graphql", "/api/graphql", "/v1/graphql", "/graph"]
        
        for ep in endpoints:
            full_url = f"{url.rstrip('/')}{ep}"
            try:
                # 1. Test Introspection
                resp = await self.http_request("POST", full_url, json={"query": self.INTROSPECTION_QUERY})
                if resp.status_code == 200 and "__schema" in resp.text:
                    findings.append(Finding(
                        id=f"gql_introspection_{hash(full_url) % 10000}",
                        agent_name=self.name,
                        title="GraphQL Introspection Enabled",
                        description="The GraphQL API has introspection enabled, allowing anyone to dump the entire schema, including types, queries, and mutations.",
                        risk_level=RiskLevel.MEDIUM,
                        evidence=f"Endpoint: {full_url}\nSchema preview: {resp.text[:500]}...",
                        remediation="Disable introspection in production environments.",
                        cwe_id="CWE-200",
                        cvss_score=5.3,
                        target_url=full_url
                    ))
                    
                # 2. Test for suggestions (Field Suggestion)
                resp = await self.http_request("POST", full_url, json={"query": "{ nonExistentField }"})
                if "Did you mean" in resp.text:
                    findings.append(Finding(
                        id=f"gql_suggestions_{hash(full_url) % 10000}",
                        agent_name=self.name,
                        title="GraphQL Field Suggestions Enabled",
                        description="The GraphQL server provides field suggestions on errors, which can aid in schema mapping even if introspection is disabled.",
                        risk_level=RiskLevel.LOW,
                        evidence=f"Error response: {resp.text[:200]}",
                        remediation="Disable field suggestions in production (e.g., using 'no-suggestions' plugin in Apollo).",
                        cwe_id="CWE-200",
                        cvss_score=3.1,
                        target_url=full_url
                    ))
            except:
                continue
                
        return findings