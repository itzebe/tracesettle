# Mission 33S — live CLI outcomes (read-only, key present)

Base URL: https://api.agentsonintents.com

## python3 -m tracesettle provider auth --base-url https://api.agentsonintents.com --json
```json
{
  "api_key_id": null,
  "authenticated": false,
  "base_url_configured": true,
  "detail": "the provider rejected the key (invalid or retired credentials)",
  "endpoint": "https://api.agentsonintents.com/v1/whoami",
  "http_status": 401,
  "key_configured": true,
  "tenant_id": null
}
```
exit=1

## python3 -m tracesettle provider agents --base-url https://api.agentsonintents.com --json
```json
{
  "agents": [],
  "availability": "UNAUTHENTICATED",
  "base_url_configured": true,
  "count": 0,
  "detail": "the provider refused the request (missing or wrong credentials)",
  "endpoint": "https://api.agentsonintents.com/v1/agents",
  "http_status": 401,
  "key_configured": true,
  "next_cursor": null
}
```
exit=1

## python3 -m tracesettle provider policy 0000000000000000000000000000000000000000000000000000000000000000 --base-url https://api.agentsonintents.com --json
```json
{
  "agent_id_requested": "0000000000000000000000000000000000000000000000000000000000000000",
  "availability": "UNAUTHENTICATED",
  "base_url_configured": true,
  "detail": "the provider refused the request (missing or wrong credentials)",
  "endpoint": "https://api.agentsonintents.com/v1/agents/0000000000000000000000000000000000000000000000000000000000000000/policy",
  "key_configured": true,
  "local_fixture": false,
  "policy": null
}
```
exit=1
