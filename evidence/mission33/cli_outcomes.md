# Mission 33 — live CLI outcomes (read-only, no key present)

Base URL: https://api.agentsonintents.com

## python3 -m tracesettle provider auth --json
{
  "api_key_id": null,
  "authenticated": false,
  "base_url_configured": true,
  "detail": "No Agent API key is configured. The provider requires X-API-Key; refusing to make an unauthenticated whoami call.",
  "endpoint": null,
  "http_status": null,
  "key_configured": false,
  "tenant_id": null
}
exit=1

## python3 -m tracesettle provider agents --json
{
  "agents": [],
  "availability": "UNAUTHENTICATED",
  "base_url_configured": true,
  "count": 0,
  "detail": "No Agent API key is configured. The provider requires X-API-Key; refusing to make an unauthenticated agent list call.",
  "endpoint": null,
  "http_status": null,
  "key_configured": false,
  "next_cursor": null
}
exit=1

## python3 -m tracesettle provider policy <agent_id> --json
{
  "agent_id_requested": "0000000000000000000000000000000000000000000000000000000000000000",
  "availability": "UNAUTHENTICATED",
  "base_url_configured": true,
  "detail": "No Agent API key is configured. The provider requires X-API-Key; refusing to make an unauthenticated read that would be reported as a policy.",
  "endpoint": null,
  "key_configured": false,
  "local_fixture": false,
  "policy": null
}
exit=1
