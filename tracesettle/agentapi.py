"""The agent-facing REST surface: a stable, versioned boundary for external agents.

An independent judge (or their agent) drives TRACESETTLE through this API. It is
deliberately narrow:

* ``POST /api/agent/connect`` mints a short-lived, scoped **sandbox credential**.
  No account, no wallet, no paid provider. It is rate-limited per client IP and
  per credential.
* ``POST /api/agent/evaluate`` evaluates a proposed transaction through the real
  guard controls and returns the decision, the reasons, and — for an ``ALLOW`` —
  a transaction-bound authorization.
* ``POST /api/agent/execute`` presents that authorization to the reference
  signer. The signer independently re-derives the binding, so an altered
  transaction is refused and the executor is never reached.
* ``POST /api/agent/approval`` mints a payload-bound human approval, but only for
  a caller holding the credential's **separate approval secret**. An agent cannot
  self-approve.
* ``GET  /api/agent/evidence`` returns that credential's own decisions and
  executor receipts — never another credential's.
* ``POST /api/agent/revoke`` revokes the presented credential.
* ``GET  /api/agent/openapi.json`` publishes the machine-readable contract.
* ``GET  /api/agent/settlement`` independently verifies the reference NEAR
  **testnet** settlement (read-only; no wallet).

Every route is read-only or sandbox-only. Nothing here signs a real transaction,
broadcasts to a chain, or accepts a client-supplied policy or approval flag as
authoritative. The credential can only ever reach the sandbox policy.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any

from .guard.sandbox import (
    SANDBOX_APPROVED_DESTINATIONS,
    SANDBOX_ATTACKER_DESTINATION,
    SandboxAuthority,
    SandboxService,
)

#: The header an agent presents its sandbox credential in.
CREDENTIAL_HEADER = "X-Sandbox-Credential"
#: The header a judge presents the credential's approval secret in.
APPROVAL_HEADER = "X-Approval-Secret"

#: How many per-credential services to keep resident. A bounded LRU, so cycling
#: credential ids cannot grow memory without bound.
_MAX_SERVICES = 64

#: The per-credential request rate (sustained/minute, burst). Separate from the
#: per-IP limit, so one credential cannot monopolise the free upstreams.
CREDENTIAL_RATE_PER_MINUTE = 60
CREDENTIAL_RATE_BURST = 15

API_VERSION = "v1"


@dataclass(frozen=True)
class AgentApiResponse:
    status: int
    payload: dict[str, Any]
    headers: dict[str, str] | None = None


def _json_error(status: int, error: str, **extra: Any) -> AgentApiResponse:
    payload: dict[str, Any] = {"error": error}
    payload.update(extra)
    return AgentApiResponse(status, payload)


class AgentAPI:
    """Dispatch the ``/api/agent`` surface. Pure routing + credential checks."""

    def __init__(
        self,
        authority: SandboxAuthority,
        *,
        settlement_reader: Any = None,
        clock: Any = None,
    ) -> None:
        self.authority = authority
        self._settlement_reader = settlement_reader
        self._lock = threading.Lock()
        self._services: "OrderedDict[str, SandboxService]" = OrderedDict()
        self._decisions: "OrderedDict[str, list[dict[str, Any]]]" = OrderedDict()
        #: Per-credential limiter, so one credential cannot monopolise upstreams.
        from .ratelimit import TokenBucketLimiter

        self._limiter = TokenBucketLimiter(
            CREDENTIAL_RATE_PER_MINUTE, CREDENTIAL_RATE_BURST
        )

    # -- service cache ------------------------------------------------------

    def _service_for(self, record: dict[str, Any]) -> SandboxService:
        credential_id = record["credential_id"]
        with self._lock:
            service = self._services.get(credential_id)
            if service is None:
                service = self.authority.build_service(credential_id, record["service_id"])
                self._services[credential_id] = service
                if len(self._services) > _MAX_SERVICES:
                    self._services.popitem(last=False)
            else:
                self._services.move_to_end(credential_id)
            return service

    def _record_decision(self, credential_id: str, entry: dict[str, Any]) -> None:
        with self._lock:
            log = self._decisions.get(credential_id)
            if log is None:
                log = []
                self._decisions[credential_id] = log
            log.append(entry)
            del log[:-50]
            if len(self._decisions) > _MAX_SERVICES:
                self._decisions.popitem(last=False)

    # -- credentials --------------------------------------------------------

    def _resolve(self, headers: dict[str, str]) -> tuple[dict[str, Any] | None, AgentApiResponse | None]:
        presented = headers.get(CREDENTIAL_HEADER)
        record, reason = self.authority.resolve(presented)
        if record is None:
            return None, _json_error(
                401,
                "sandbox credential refused",
                reason=reason,
                hint=(
                    "Mint a credential at POST /api/agent/connect and present it in the "
                    f"{CREDENTIAL_HEADER} header."
                ),
            )
        credential_id = record["credential_id"]
        if not self._limiter.allow(credential_id):
            retry = self._limiter.retry_after_seconds(credential_id)
            return None, AgentApiResponse(
                429,
                {"error": "credential rate limit exceeded; retry later"},
                {"Retry-After": str(retry)},
            )
        return record, None

    # -- GET ----------------------------------------------------------------

    def get(self, path: str, params: dict[str, str], headers: dict[str, str]) -> AgentApiResponse:
        if path == "/api/agent/config":
            return AgentApiResponse(200, self._config())
        if path == "/api/agent/openapi.json":
            return AgentApiResponse(200, self.openapi())
        if path == "/api/agent/settlement":
            return self._settlement()
        if path == "/api/agent/evidence":
            record, refusal = self._resolve(headers)
            if refusal is not None:
                return refusal
            return self._evidence(record)
        return _json_error(404, "not found")

    def post(
        self, path: str, params: dict[str, str], body: Any, headers: dict[str, str]
    ) -> AgentApiResponse:
        if path == "/api/agent/connect":
            return self._connect(body)
        if path == "/api/agent/evaluate":
            record, refusal = self._resolve(headers)
            if refusal is not None:
                return refusal
            return self._evaluate(record, body)
        if path == "/api/agent/execute":
            record, refusal = self._resolve(headers)
            if refusal is not None:
                return refusal
            return self._execute(record, body)
        if path == "/api/agent/approval":
            record, refusal = self._resolve(headers)
            if refusal is not None:
                return refusal
            return self._approval(record, body, headers)
        if path == "/api/agent/revoke":
            record, refusal = self._resolve(headers)
            if refusal is not None:
                return refusal
            self.authority.revoke(record["credential_id"])
            return AgentApiResponse(200, {"revoked": True, "credential_id": record["credential_id"]})
        return _json_error(404, "not found")

    # -- handlers -----------------------------------------------------------

    def _connect(self, body: Any) -> AgentApiResponse:
        label = "judge"
        if isinstance(body, dict) and isinstance(body.get("label"), str) and body["label"].strip():
            label = body["label"].strip()
        elif isinstance(body, str) and body.strip():
            label = body.strip()
        credential = self.authority.mint(label=label)
        public = credential.to_public_dict()
        public["endpoints"] = self._endpoint_map()
        public["approved_destinations"] = list(SANDBOX_APPROVED_DESTINATIONS)
        public["example_blocked_destination"] = SANDBOX_ATTACKER_DESTINATION
        public["durable"] = self.authority.durable
        return AgentApiResponse(201, public)

    def _identity_ok(self, record: dict[str, Any], body: Any) -> AgentApiResponse | None:
        if not isinstance(body, dict):
            return _json_error(400, "request body must be a JSON object")
        declared = body.get("service_id")
        if declared is not None and str(declared) != record["service_id"]:
            return _json_error(
                403,
                "the request names a service identity this credential was not issued for",
                credential_service_id=record["service_id"],
            )
        return None

    def _evaluate(self, record: dict[str, Any], body: Any) -> AgentApiResponse:
        refusal = self._identity_ok(record, body)
        if refusal is not None:
            return refusal
        transaction = self._transaction(body)
        if transaction is None:
            return _json_error(400, "field 'transaction' must be a JSON object")
        transaction["service_id"] = record["service_id"]
        service = self._service_for(record)
        # A presented approval is honoured only for a REQUIRE_APPROVAL decision and
        # only when bound to this exact payload, so it can raise that decision to
        # ALLOW and mint an authorization. It can never override a BLOCK.
        approval = body.get("approval") if isinstance(body, dict) else None
        decision = service.decide(transaction, approval=approval)
        self.authority.touch(record["credential_id"])
        self._record_decision(
            record["credential_id"],
            {
                "kind": "evaluate",
                "decision": decision.get("decision"),
                "transaction": {
                    k: transaction.get(k)
                    for k in ("operation", "chain", "asset", "amount", "destination")
                },
            },
        )
        return AgentApiResponse(200, decision)

    def _execute(self, record: dict[str, Any], body: Any) -> AgentApiResponse:
        refusal = self._identity_ok(record, body)
        if refusal is not None:
            return refusal
        transaction = self._transaction(body)
        if transaction is None:
            return _json_error(400, "field 'transaction' must be a JSON object")
        transaction["service_id"] = record["service_id"]
        service = self._service_for(record)
        approval = body.get("approval")
        result = service.execute(transaction, body.get("authorization"), approval=approval)
        if "error" in result and result.get("status") == 400:
            return _json_error(400, result["error"])
        self.authority.touch(record["credential_id"])
        sign = result.get("sign_result") or {}
        self._record_decision(
            record["credential_id"],
            {
                "kind": "execute",
                "outcome": sign.get("outcome"),
                "state": sign.get("state"),
                "executor_calls": result.get("executor_calls"),
            },
        )
        return AgentApiResponse(200, result)

    def _approval(self, record: dict[str, Any], body: Any, headers: dict[str, str]) -> AgentApiResponse:
        refusal = self._identity_ok(record, body)
        if refusal is not None:
            return refusal
        if not self.authority.resolve_approval(
            record["credential_id"], headers.get(APPROVAL_HEADER)
        ):
            # The approval secret is separate from the credential on purpose, so
            # an agent cannot mint its own approval with the credential it uses
            # to evaluate. Missing it is a refusal, never a bypass.
            return _json_error(
                403,
                "the approval secret is required and must match this credential",
                hint=f"present the credential's approval secret in {APPROVAL_HEADER}",
            )
        transaction = self._transaction(body)
        if transaction is None:
            return _json_error(400, "field 'transaction' must be a JSON object")
        transaction["service_id"] = record["service_id"]
        approver = body.get("approver") if isinstance(body.get("approver"), str) else "judge"
        service = self._service_for(record)
        approval = service.approve(transaction, approver=approver or "judge")
        if isinstance(approval, dict) and "error" in approval:
            return _json_error(400, approval["error"])
        return AgentApiResponse(
            200,
            {
                "approval": approval,
                "note": (
                    "A human approval bound to this exact payload. Present it as 'approval' to "
                    "POST /api/agent/execute to raise a REQUIRE_APPROVAL decision to ALLOW."
                ),
            },
        )

    def _evidence(self, record: dict[str, Any]) -> AgentApiResponse:
        service = self._service_for(record)
        receipts = [r.to_dict() for r in service.executor.receipts()]
        with self._lock:
            decisions = list(self._decisions.get(record["credential_id"], []))
        return AgentApiResponse(
            200,
            {
                "credential_id": record["credential_id"],
                "service_id": record["service_id"],
                "executor_receipts": receipts,
                "executor_calls": len(receipts),
                "decisions": decisions,
                "broadcast": False,
                "simulated": True,
                "note": (
                    "This credential's own evidence only. Executor receipts are simulated: "
                    "they record what the executor was asked to do and never produce a "
                    "blockchain transaction hash."
                ),
            },
        )

    def _settlement(self) -> AgentApiResponse:
        if self._settlement_reader is None:
            return AgentApiResponse(
                503,
                {
                    "state": "UNAVAILABLE",
                    "verified": False,
                    "note": "settlement verification is not configured on this deployment",
                },
            )
        try:
            check = self._settlement_reader()
        except Exception as exc:  # noqa: BLE001 - a reader failure is not a verification
            return AgentApiResponse(
                503,
                {
                    "state": "UNAVAILABLE",
                    "verified": False,
                    "note": f"settlement verification could not run: {type(exc).__name__}",
                },
            )
        payload = check.to_dict() if hasattr(check, "to_dict") else dict(check)
        return AgentApiResponse(200, payload)

    # -- helpers ------------------------------------------------------------

    @staticmethod
    def _transaction(body: Any) -> dict[str, Any] | None:
        if not isinstance(body, dict):
            return None
        nested = body.get("transaction")
        if isinstance(nested, dict):
            return dict(nested)
        # Accept the transaction fields at the top level as a convenience.
        return {
            k: v
            for k, v in body.items()
            if k not in {"authorization", "approval", "approver"}
        }

    def _endpoint_map(self) -> dict[str, str]:
        return {
            "evaluate": "POST /api/agent/evaluate",
            "execute": "POST /api/agent/execute",
            "approval": "POST /api/agent/approval",
            "evidence": "GET /api/agent/evidence",
            "revoke": "POST /api/agent/revoke",
            "settlement": "GET /api/agent/settlement",
            "config": "GET /api/agent/config",
            "openapi": "GET /api/agent/openapi.json",
        }

    def _config(self) -> dict[str, Any]:
        return {
            "api_version": API_VERSION,
            "credential_header": CREDENTIAL_HEADER,
            "approval_header": APPROVAL_HEADER,
            "endpoints": self._endpoint_map(),
            "credential_lifetime_seconds": self.authority.ttl_seconds,
            "max_requests_per_credential": self.authority.max_requests,
            "durable_credentials": self.authority.durable,
            "sandbox": {
                "approved_destinations": list(SANDBOX_APPROVED_DESTINATIONS),
                "blocked_example_destination": SANDBOX_ATTACKER_DESTINATION,
                "per_transaction_limit": "500",
                "approval_threshold": "100",
                "note": (
                    "The sandbox policy is real and enforced. A payment to an approved "
                    "destination within the limit is ALLOW; anything else is BLOCK or "
                    "REQUIRE_APPROVAL because the policy refuses it."
                ),
            },
            "honest_scope": (
                "Sandbox execution is simulated: the authorization boundary, signer refusal "
                "logic and replay store are the real production code, but no transaction is "
                "signed or broadcast. Live wallet signing and mainnet are not exposed."
            ),
        }

    def openapi(self) -> dict[str, Any]:
        """The machine-readable contract for the agent surface."""
        return {
            "openapi": "3.1.0",
            "info": {
                "title": "TRACESETTLE agent integration API",
                "version": API_VERSION,
                "description": (
                    "A scoped, sandbox integration boundary so an external agent can have a "
                    "proposed payment independently evaluated before it is signed. Sandbox "
                    "only: no real signing, no broadcast, no private key."
                ),
            },
            "servers": [{"url": "/"}],
            "components": {
                "securitySchemes": {
                    "SandboxCredential": {
                        "type": "apiKey",
                        "in": "header",
                        "name": CREDENTIAL_HEADER,
                    },
                    "ApprovalSecret": {
                        "type": "apiKey",
                        "in": "header",
                        "name": APPROVAL_HEADER,
                    },
                },
                "schemas": {
                    "Transaction": {
                        "type": "object",
                        "required": ["operation", "chain", "asset", "amount", "destination"],
                        "properties": {
                            "operation": {"type": "string", "example": "WITHDRAWAL"},
                            "chain": {"type": "string", "example": "base"},
                            "asset": {"type": "string", "example": "USDC"},
                            "amount": {"type": "string", "example": "50"},
                            "destination": {"type": "string"},
                            "service_id": {
                                "type": "string",
                                "description": "Must match the credential's service identity.",
                            },
                            "request_id": {"type": "string"},
                        },
                    }
                },
            },
            "paths": {
                "/api/agent/connect": {
                    "post": {
                        "summary": "Mint a short-lived sandbox credential",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {"label": {"type": "string"}},
                                    }
                                }
                            }
                        },
                        "responses": {"201": {"description": "A scoped credential"}},
                    }
                },
                "/api/agent/evaluate": {
                    "post": {
                        "summary": "Evaluate a proposed transaction",
                        "security": [{"SandboxCredential": []}],
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "transaction": {"$ref": "#/components/schemas/Transaction"}
                                        },
                                    }
                                }
                            }
                        },
                        "responses": {"200": {"description": "The decision and evidence"}},
                    }
                },
                "/api/agent/execute": {
                    "post": {
                        "summary": "Present an authorization to the signer",
                        "security": [{"SandboxCredential": []}],
                        "responses": {"200": {"description": "Signer result and executor calls"}},
                    }
                },
                "/api/agent/approval": {
                    "post": {
                        "summary": "Mint a payload-bound approval (requires the approval secret)",
                        "security": [{"SandboxCredential": []}, {"ApprovalSecret": []}],
                        "responses": {"200": {"description": "An approval bound to the payload"}},
                    }
                },
                "/api/agent/evidence": {
                    "get": {
                        "summary": "This credential's decisions and executor receipts",
                        "security": [{"SandboxCredential": []}],
                        "responses": {"200": {"description": "Evidence"}},
                    }
                },
                "/api/agent/revoke": {
                    "post": {
                        "summary": "Revoke the presented credential",
                        "security": [{"SandboxCredential": []}],
                        "responses": {"200": {"description": "Revoked"}},
                    }
                },
                "/api/agent/settlement": {
                    "get": {
                        "summary": "Verify the reference NEAR testnet settlement (read-only)",
                        "responses": {"200": {"description": "Settlement state"}},
                    }
                },
            },
        }
