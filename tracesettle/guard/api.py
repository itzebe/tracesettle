"""HTTP-facing API for the transaction security layer.

Pure routing and serialization: the handler in :mod:`tracesettle.ui` owns the
socket, the authentication, and the rate limits, and calls :meth:`GuardAPI.dispatch`.
Keeping the mapping here makes every endpoint testable without a socket.

No endpoint returns the signing key, and no endpoint accepts a client-supplied
approval flag as meaningful. ``POST /api/guard/evaluate`` returns the issued
authorization only when ``return_authorization`` is true, so an operator can
hand it to a signer; it is a bearer token with a short life, not a secret store.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .model import IncidentStatus, TransactionRequest
from .service import GuardService, RequestValidationError, request_from_payload
from .signer import SignRequest

MAX_LIMIT = 200


@dataclass(frozen=True)
class ApiResponse:
    status: int
    payload: dict[str, Any]
    headers: dict[str, str] = field(default_factory=dict)


def _bad_request(message: str) -> ApiResponse:
    return ApiResponse(400, {"error": message})


def _int_param(params: dict[str, str], name: str, default: int, *, low: int, high: int) -> int:
    raw = params.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise RequestValidationError(f"query parameter '{name}' must be an integer")
    if value < low or value > high:
        raise RequestValidationError(f"query parameter '{name}' must be between {low} and {high}")
    return value


class GuardAPI:
    """Routes guard requests to the service and serializes the results."""

    def __init__(
        self, service: GuardService, lifecycle: Any = None, investigation_store: Any = None
    ) -> None:
        self.service = service
        #: The optional durable settlement-investigation store. When set, a
        #: completed investigation is retrievable later, across a restart.
        self.investigation_store = investigation_store
        #: The optional NEAR Intents lifecycle. Built only when the operator has
        #: enabled it and configured a durable store, so a deployment that does
        #: not offer the lifecycle pays nothing and exposes no route.
        self.lifecycle = lifecycle

    def dispatch(
        self,
        method: str,
        path: str,
        params: dict[str, str],
        body: Any,
        *,
        authenticated_service_id: str | None = None,
    ) -> ApiResponse:
        method = method.upper()
        try:
            return self._dispatch(method, path, params, body, authenticated_service_id)
        except RequestValidationError as exc:
            return _bad_request(str(exc))

    def _dispatch(
        self,
        method: str,
        path: str,
        params: dict[str, str],
        body: Any,
        authenticated_service_id: str | None = None,
    ) -> ApiResponse:
        if method == "GET":
            return self._get(path, params)
        if method == "POST":
            return self._post(path, params, body, authenticated_service_id)
        return ApiResponse(405, {"error": "method not allowed"})

    @staticmethod
    def _declared_service_id(body: Any) -> str | None:
        """The service identity a request declares, across both body shapes.

        ``/api/guard/evaluate`` accepts the transaction fields at the top level
        or under ``transaction``; ``/api/guard/sign`` always nests them. This
        finds the declared identity in either form.
        """
        if not isinstance(body, dict):
            return None
        nested = body.get("transaction")
        source = nested if isinstance(nested, dict) else body
        declared = source.get("service_id")
        if isinstance(declared, str) and declared.strip():
            return declared.strip()
        return None

    @classmethod
    def _identity_matches(cls, body: Any, authenticated_service_id: str | None) -> bool:
        """Whether the request's declared identity matches the authenticated one.

        When authentication is disabled (``None``) there is nothing to compare
        against, so the declared identity stands. When it is enabled, a request
        that declares a different service than its credential was issued for is
        refused: this is the impersonation case, and it is checked here so the
        policy layer never sees a forged identity even if a caller reaches the
        API directly.
        """
        if authenticated_service_id is None:
            return True
        declared = cls._declared_service_id(body)
        if declared is None:
            return False
        return declared == authenticated_service_id

    # -- GET ----------------------------------------------------------------

    def _get(self, path: str, params: dict[str, str]) -> ApiResponse:
        if path == "/api/guard/policy":
            return ApiResponse(200, {"policy": self.service.policy.to_dict()})
        if path == "/api/guard/metrics":
            return ApiResponse(200, self.service.metrics())
        if path == "/api/guard/incidents":
            status = params.get("status")
            parsed = None
            if status:
                try:
                    parsed = IncidentStatus(status.upper())
                except ValueError:
                    return _bad_request("query parameter 'status' must be OPEN, ACKNOWLEDGED or RESOLVED")
            limit = _int_param(params, "limit", 100, low=1, high=MAX_LIMIT)
            incidents = self.service.incidents(status=parsed, limit=limit)
            return ApiResponse(200, {"incidents": [i.to_dict() for i in incidents]})
        if path == "/api/guard/audit":
            limit = _int_param(params, "limit", 100, low=1, high=MAX_LIMIT)
            records = self.service.audit_records(limit=limit)
            payload: dict[str, Any] = {"records": [r.to_dict() for r in records]}
            if params.get("verify") in ("1", "true", "yes"):
                payload["verification"] = self.service.audit_verification().to_dict()
            return ApiResponse(200, payload)
        if path == "/api/guard/scenarios":
            return ApiResponse(200, {"scenarios": SCENARIOS, "note": SIMULATION_NOTE})
        if path == "/api/guard/near/scenarios":
            from ..near.attacks import SIMULATION_NOTE as NEAR_NOTE
            from ..near.attacks import run_all

            results = run_all()
            return ApiResponse(
                200,
                {
                    "note": NEAR_NOTE,
                    "results": [r.to_dict() for r in results],
                    "all_passed": all(r.passed for r in results),
                },
            )
        if path == "/api/guard/near/access-keys":
            return ApiResponse(200, {"keys": self._near_access_keys()})
        if path == "/api/guard/near/policy-scope":
            return ApiResponse(200, self._near_policy_scope())
        if path == "/api/guard/near/settlement-demo":
            return ApiResponse(200, self._near_settlement_demo())
        if path == "/api/guard/near/lifecycle":
            return self._lifecycle_list(params)
        if path == "/api/guard/near/lifecycle/tokens":
            return self._lifecycle_tokens()
        if path.startswith("/api/guard/near/lifecycle/"):
            intent_id = path[len("/api/guard/near/lifecycle/") :].strip("/")
            return self._lifecycle_get(intent_id)
        if path == "/api/guard/investigations":
            return self._investigations_list()
        if path.startswith("/api/guard/investigations/"):
            return self._investigation_get(path[len("/api/guard/investigations/"):])
        if path == "/api/guard/invariants":
            from .invariants import INVARIANT_DESCRIPTIONS, check_all

            results = check_all()
            return ApiResponse(
                200,
                {
                    "invariants": [
                        {
                            **r.to_dict(),
                            "statement": INVARIANT_DESCRIPTIONS.get(r.name, ""),
                        }
                        for r in results
                    ],
                    "all_hold": all(r.holds for r in results),
                },
            )
        if path == "/api/guard/safeguards":
            return ApiResponse(
                200,
                {
                    "enabled": self.service.learning.enabled,
                    "safeguards": [s.to_dict() for s in self.service.learning.list()],
                    "note": (
                        "Durable safeguards learned from security failures. They only ever "
                        "tighten a decision and never replace the operator's policy."
                    ),
                },
            )
        return ApiResponse(404, {"error": "not found"})

    # -- NEAR helpers -------------------------------------------------------

    @staticmethod
    def _near_fixture_dir() -> Any:
        """The NEAR fixtures, shipped inside the package.

        They live in ``tracesettle/near/fixtures`` rather than under ``tests/``
        so a container that copies only the package (the production image) can
        still serve these endpoints. Loading them from ``tests/`` made three
        routes raise ``FileNotFoundError`` in the image and drop the connection.
        """
        import pathlib

        return pathlib.Path(__file__).resolve().parents[1] / "near" / "fixtures"

    def _near_access_keys(self) -> dict[str, Any]:
        """Analyse the documented access-key shapes. Fixtures, clearly labelled."""
        import json

        from ..near.access_keys import parse_access_key

        raw = json.loads((self._near_fixture_dir() / "access_keys.json").read_text())
        return {
            "note": (
                "Synthetic fixtures reproducing the documented NEAR access-key permission shapes. "
                "No private key material is present or requested."
            ),
            "keys": {
                name: parse_access_key(shape).to_dict()
                for name, shape in raw.get("keys", {}).items()
            },
        }

    def _near_policy_scope(self) -> dict[str, Any]:
        """Report which policy controls protect each transaction path."""
        import json

        from ..near.policy import (
            PolicyAdapter,
            PolicyScope,
            controls_applicable_to,
            controls_not_applicable_to,
        )

        raw = json.loads((self._near_fixture_dir() / "policy_in_force.json").read_text())
        read = PolicyAdapter.from_fixture(raw)
        return {
            "note": (
                "The NEAR Intents policy protects the INTENTS path. Native NEAR/EVM/Solana "
                "requests skip destinations, budget, timelock, schedule and owner approval; only "
                "the policy's native method switch and an independent TraceSettle decision govern."
            ),
            "policy": read.to_dict(),
            "scope": {
                scope.value: {
                    "applicable_controls": list(controls_applicable_to(scope)),
                    "non_applicable_controls": list(controls_not_applicable_to(scope)),
                }
                for scope in PolicyScope
            },
        }

    def _near_settlement_demo(self) -> dict[str, Any]:
        """The post-settlement assurance view: a provider claim is never proof.

        Runs the deterministic engine over a synthetic evidence set in which the
        provider reports success but no decisive on-chain evidence exists, and
        reports the honest assurance level (UNKNOWN, not VERIFIED).
        """
        from ..near.settlement import settlement_assurance_from_result
        from ..reconcile import reconcile

        from ..model import SourceStatus

        result = reconcile(
            [],
            {"oneclick_status": SourceStatus.RATE_LIMITED},
            expected_intent_hashes=[],
            expected_origin_tx_hashes=[],
        )
        assurance = settlement_assurance_from_result(result, provider_reported_success=True)
        return {
            "note": (
                "A provider success status is a REPORTED claim, never independent settlement "
                "proof. This synthetic case has the provider report success with no decisive "
                "on-chain evidence, so the assurance level is not VERIFIED."
            ),
            "provider_reported_success": True,
            "assurance": assurance.to_dict(),
        }

    # -- POST ---------------------------------------------------------------

    def _post(
        self,
        path: str,
        params: dict[str, str],
        body: Any,
        authenticated_service_id: str | None = None,
    ) -> ApiResponse:
        if path == "/api/guard/evaluate":
            if not self._identity_matches(body, authenticated_service_id):
                return ApiResponse(403, {"error": "service identity does not match the credential"})
            return self._evaluate(body)
        if path == "/api/guard/sign":
            if not self._identity_matches(body, authenticated_service_id):
                return ApiResponse(403, {"error": "service identity does not match the credential"})
            return self._sign(body, authenticated_service_id)
        if path == "/api/guard/near/agent-evaluate":
            if not self._identity_matches(body, authenticated_service_id):
                return ApiResponse(403, {"error": "service identity does not match the credential"})
            return self._near_agent_evaluate(body)
        if path == "/api/guard/near/lifecycle":
            return self._lifecycle_create(body, authenticated_service_id)
        if path == "/api/guard/near/lifecycle/list":
            return self._lifecycle_list_owned(body, authenticated_service_id)
        if path.startswith("/api/guard/near/lifecycle/"):
            return self._lifecycle_action(path, body, authenticated_service_id)
        if path.startswith("/api/guard/incidents/") and path.endswith("/status"):
            incident_id = path[len("/api/guard/incidents/") : -len("/status")].strip("/")
            return self._incident_status(incident_id, body)
        return ApiResponse(404, {"error": "not found"})

    def _evaluate(self, body: Any) -> ApiResponse:
        if not isinstance(body, dict):
            return _bad_request("request body must be a JSON object")
        simulated = bool(body.get("simulated", False))
        return_authorization = bool(body.get("return_authorization", False))
        transaction = body.get("transaction")
        if transaction is None:
            # Accept the transaction fields at the top level as a convenience.
            transaction = {
                k: v for k, v in body.items() if k not in {"simulated", "return_authorization"}
            }
        if not isinstance(transaction, dict):
            return _bad_request("field 'transaction' must be a JSON object")
        decision = self.service.evaluate_payload(transaction, simulated=simulated)
        return ApiResponse(200, decision.to_dict(include_authorization=return_authorization))

    def _sign(self, body: Any, authenticated_service_id: str | None = None) -> ApiResponse:
        if not isinstance(body, dict):
            return _bad_request("request body must be a JSON object")
        raw_transaction = body.get("transaction")
        if not isinstance(raw_transaction, dict):
            return _bad_request("field 'transaction' must be a JSON object")
        simulated = bool(body.get("simulated", raw_transaction.get("simulated", False)))
        try:
            transaction: TransactionRequest = request_from_payload(
                raw_transaction, simulated=simulated
            )
        except RequestValidationError as exc:
            return _bad_request(str(exc))
        # The expected service identity is the *authenticated* caller, never a
        # body field: a caller must not be able to make the signer validate (and,
        # on refusal, attribute the rejection) against a service it is not. When
        # service authentication is disabled (loopback default) there is no
        # authenticated identity, so the caller's declared identity stands.
        expected_service_id = (
            authenticated_service_id
            if authenticated_service_id is not None
            else body.get("expected_service_id")
        )
        result = self.service.sign(
            SignRequest(
                transaction=transaction,
                authorization=body.get("authorization"),
                expected_service_id=expected_service_id,
            )
        )
        return ApiResponse(200, result.to_dict())

    def _near_agent_evaluate(self, body: Any) -> ApiResponse:
        """Evaluate an agent transaction through the NEAR wrapper.

        The wrapper inspects the real transaction parameters, the NEAR Intents
        policy scope, and the access-key scope. It returns one of ALLOW,
        REQUIRE_APPROVAL, BLOCK, HOLD or UNKNOWN. The transaction is never
        signed or broadcast here.
        """
        if not isinstance(body, dict):
            return _bad_request("request body must be a JSON object")
        transaction = body.get("transaction")
        if not isinstance(transaction, dict):
            return _bad_request("field 'transaction' must be a JSON object")
        try:
            decision = self.service.evaluate_agent_transaction(
                transaction,
                policy_read=self._near_policy_read(body),
                access_key=self._near_access_key(body),
            )
        except RequestValidationError as exc:
            return _bad_request(str(exc))
        return ApiResponse(
            200,
            decision.to_dict(include_authorization=bool(body.get("return_authorization", False))),
        )

    # -- NEAR Intents lifecycle --------------------------------------------

    def _lifecycle_owner(self, authenticated_service_id: str | None, body: Any) -> str | None:
        """The owner a lifecycle record belongs to.

        When service authentication is enabled the owner is the authenticated
        identity, never a body field, so one service can never read another's
        investigations. When it is disabled (loopback) the caller's declared
        ``owner`` or ``service_id`` is used, defaulting to ``local``.
        """
        if authenticated_service_id is not None:
            return authenticated_service_id
        if isinstance(body, dict):
            declared = body.get("owner") or body.get("service_id")
            if isinstance(declared, str) and declared.strip():
                return declared.strip()
        return "local"

    def _require_lifecycle(self) -> ApiResponse | None:
        if self.lifecycle is None:
            return ApiResponse(
                404,
                {
                    "error": "the NEAR Intents lifecycle is not enabled",
                    "hint": "set TRACESETTLE_NEAR_LIFECYCLE=1 and TRACESETTLE_INTENTS_DB=<path>",
                },
            )
        return None

    def _lifecycle_list(self, params: dict[str, str]) -> ApiResponse:
        refused = self._require_lifecycle()
        if refused is not None:
            return refused
        # A GET carries no credential, so it is scoped to the ``local`` owner and
        # a query parameter cannot widen it. An authenticated service lists its
        # own records with ``POST /api/guard/near/lifecycle/list``.
        limit = _int_param(params, "limit", 50, low=1, high=MAX_LIMIT)
        return ApiResponse(200, {"owner": "local", "intents": self.lifecycle.list(owner="local", limit=limit)})

    def _lifecycle_list_owned(self, body: Any, authenticated_service_id: str | None) -> ApiResponse:
        refused = self._require_lifecycle()
        if refused is not None:
            return refused
        owner = self._lifecycle_owner(authenticated_service_id, body)
        limit = 50
        if isinstance(body, dict) and body.get("limit") is not None:
            try:
                limit = int(body["limit"])
            except (TypeError, ValueError):
                return _bad_request("field 'limit' must be an integer")
            if limit < 1 or limit > MAX_LIMIT:
                return _bad_request(f"field 'limit' must be between 1 and {MAX_LIMIT}")
        return ApiResponse(200, {"owner": owner, "intents": self.lifecycle.list(owner=owner, limit=limit)})

    def _lifecycle_tokens(self) -> ApiResponse:
        refused = self._require_lifecycle()
        if refused is not None:
            return refused
        data = self.lifecycle.assets()
        return ApiResponse(200, data)

    # -- durable settlement-investigation history --------------------------

    def _investigations_list(self) -> ApiResponse:
        """List the stored investigations for the local owner (read-only)."""
        if self.investigation_store is None:
            return ApiResponse(
                200,
                {
                    "enabled": False,
                    "owner": "local",
                    "investigations": [],
                    "note": (
                        "durable investigation history is not configured; set "
                        "TRACESETTLE_INVESTIGATIONS_DB to retain reports across a restart"
                    ),
                },
            )
        return ApiResponse(
            200,
            {
                "enabled": True,
                "owner": "local",
                "investigations": self.investigation_store.list_for_owner("local"),
            },
        )

    def _investigation_get(self, investigation_id: str) -> ApiResponse:
        """Return one stored investigation report, with its evidence intact."""
        if self.investigation_store is None:
            return ApiResponse(
                404,
                {"error": "durable investigation history is not configured"},
            )
        investigation_id = investigation_id.strip("/")
        if not investigation_id or len(investigation_id) > 200:
            return _bad_request("invalid investigation id")
        report = self.investigation_store.get(investigation_id, owner="local")
        if report is None:
            return ApiResponse(404, {"error": "no such investigation"})
        return ApiResponse(200, {"investigation": report})

    def _lifecycle_get(self, intent_id: str) -> ApiResponse:
        refused = self._require_lifecycle()
        if refused is not None:
            return refused
        # A read has no body, so it is scoped to the ``local`` owner; a service
        # identity that wants its own records uses the POST actions with a credential.
        record = self.lifecycle.get(owner="local", intent_id=intent_id)
        if record is None:
            return ApiResponse(404, {"error": "no such intent"})
        return ApiResponse(200, {"intent": record})

    def _lifecycle_create(self, body: Any, authenticated_service_id: str | None) -> ApiResponse:
        refused = self._require_lifecycle()
        if refused is not None:
            return refused
        if not isinstance(body, dict):
            return _bad_request("request body must be a JSON object")
        owner = self._lifecycle_owner(authenticated_service_id, body)
        transaction = body.get("transaction")
        if not isinstance(transaction, dict):
            return _bad_request("field 'transaction' must be a JSON object")
        if not self._identity_matches(body, authenticated_service_id) and not self._identity_matches(
            transaction, authenticated_service_id
        ):
            return ApiResponse(403, {"error": "service identity does not match the credential"})
        # A top-level ``idempotency_key`` is accepted so a caller can make a retried
        # or double-submitted create idempotent without duplicating the field inside
        # the transaction. An explicit transaction-level key wins.
        idem = body.get("idempotency_key")
        if idem and not transaction.get("idempotency_key"):
            transaction = dict(transaction)
            transaction["idempotency_key"] = str(idem)
        try:
            result = self.lifecycle.create_and_authorize(
                owner=owner,
                payload=transaction,
                policy_read=self._near_policy_read(body),
                access_key=self._near_access_key(body),
            )
        except Exception as exc:  # noqa: BLE001 - LifecycleError and validation both carry safe text
            return _bad_request(str(exc))
        return ApiResponse(200, result)

    def _lifecycle_action(self, path: str, body: Any, authenticated_service_id: str | None) -> ApiResponse:
        refused = self._require_lifecycle()
        if refused is not None:
            return refused
        if not isinstance(body, dict):
            return _bad_request("request body must be a JSON object")
        rest = path[len("/api/guard/near/lifecycle/") :].strip("/")
        if "/" not in rest:
            return ApiResponse(404, {"error": "not found"})
        intent_id, action = rest.rsplit("/", 1)
        owner = self._lifecycle_owner(authenticated_service_id, body)
        try:
            if action == "quote":
                return ApiResponse(
                    200,
                    self.lifecycle.request_quote(
                        owner=owner, intent_id=intent_id, dry=bool(body.get("dry", False))
                    ),
                )
            if action == "approve":
                return ApiResponse(
                    200,
                    self.lifecycle.approve_quote(
                        owner=owner, intent_id=intent_id, approve=bool(body.get("approve", True))
                    ),
                )
            if action == "deposit":
                return ApiResponse(
                    200,
                    self.lifecycle.record_deposit(
                        owner=owner,
                        intent_id=intent_id,
                        deposit_tx_hash=str(body.get("deposit_tx_hash") or ""),
                        near_sender_account=(
                            str(body["near_sender_account"]) if body.get("near_sender_account") else None
                        ),
                    ),
                )
            if action == "status":
                return ApiResponse(200, self.lifecycle.refresh_status(owner=owner, intent_id=intent_id))
            if action == "verify-origin":
                record = self.lifecycle.get(owner=owner, intent_id=intent_id)
                if record is None:
                    return ApiResponse(404, {"error": "no such intent"})
                verification = self.lifecycle.origin_verification(owner=owner, intent_id=intent_id)
                if verification is None:
                    return _bad_request("no deposit transaction hash has been recorded for this intent")
                return ApiResponse(200, {"intent_id": intent_id, "origin_verification": verification})
            if action == "verify-destination":
                record = self.lifecycle.get(owner=owner, intent_id=intent_id)
                if record is None:
                    return ApiResponse(404, {"error": "no such intent"})
                verification = self.lifecycle.destination_verification(
                    owner=owner, intent_id=intent_id
                )
                if verification is None:
                    return _bad_request(
                        "no destination transaction hash is known for this intent; read the "
                        "provider status first"
                    )
                return ApiResponse(
                    200, {"intent_id": intent_id, "destination_verification": verification}
                )
            if action == "assurance":
                return ApiResponse(200, self.lifecycle.assurance(owner=owner, intent_id=intent_id))
            if action == "get":
                record = self.lifecycle.get(owner=owner, intent_id=intent_id)
                if record is None:
                    return ApiResponse(404, {"error": "no such intent"})
                return ApiResponse(200, {"intent": record})
        except Exception as exc:  # noqa: BLE001 - safe message
            return _bad_request(str(exc))
        return ApiResponse(404, {"error": "not found"})

    def _near_policy_read(self, body: Any) -> Any:
        """Resolve the policy read from the *server's* configuration.

        The policy a request is judged against is part of the enforcement
        decision, so the caller must not choose it. Resolution order:

        1. ``TRACESETTLE_NEAR_POLICY_FIXTURE`` — the operator's pinned fixture.
        2. The configured Agent API (``TRACESETTLE_NEAR_AGENT_API_URL``).
        3. Nothing, so the guard's own policy governs.

        A request body may name ``policy_fixture`` or ``agent_id`` only when
        ``TRACESETTLE_NEAR_ALLOW_CLIENT_POLICY_SELECTION`` is explicitly on, a
        loopback-only affordance for exploring alternative policies. Honouring
        them by default let a caller replace a restrictive operator policy with
        a permissive one and turn a BLOCK into an ALLOW.
        """
        from .. import config
        from ..near.policy import PolicyAdapter, load_fixture

        allow_client_selection = bool(config.NEAR_ALLOW_CLIENT_POLICY_SELECTION)

        fixture = body.get("policy_fixture") if allow_client_selection else None
        if isinstance(fixture, str) and fixture.strip():
            return load_fixture(fixture.strip())
        if config.NEAR_POLICY_FIXTURE:
            return load_fixture(config.NEAR_POLICY_FIXTURE)
        if config.NEAR_AGENT_API_URL:
            adapter = PolicyAdapter(
                base_url=config.NEAR_AGENT_API_URL,
                api_key=config.NEAR_AGENT_API_KEY,
                http_client=self.service.http_client,
            )
            agent_id = (
                body.get("agent_id") if allow_client_selection else None
            ) or config.NEAR_AGENT_ID
            return adapter.read_policy(str(agent_id))
        return None

    @staticmethod
    def _near_access_key(body: Any) -> Any:
        from ..near.access_keys import parse_access_key

        raw = body.get("access_key")
        if raw is None:
            return None
        try:
            return parse_access_key(raw)
        except ValueError as exc:
            raise RequestValidationError(f"field 'access_key': {exc}") from exc

    def _incident_status(self, incident_id: str, body: Any) -> ApiResponse:
        if not incident_id:
            return _bad_request("an incident id is required in the path")
        if not isinstance(body, dict):
            return _bad_request("request body must be a JSON object")
        raw = body.get("status")
        if not isinstance(raw, str):
            return _bad_request("field 'status' must be a string")
        try:
            status = IncidentStatus(raw.upper())
        except ValueError:
            return _bad_request("field 'status' must be OPEN, ACKNOWLEDGED or RESOLVED")
        updated = self.service.set_incident_status(incident_id, status)
        if updated is None:
            return ApiResponse(404, {"error": "unknown incident"})
        return ApiResponse(200, {"incident": updated.to_dict()})


#: Labelled, controlled scenarios. Each is a *simulation*: the requests are
#: synthetic and the executor is simulated. They exist to demonstrate the
#: enforcement boundary, never to stand in for a real transaction.
SIMULATION_NOTE = (
    "These scenarios are controlled simulations. The transaction parameters are synthetic, the "
    "executor is simulated, and nothing is broadcast to any chain. A simulated result never "
    "describes a real blockchain transaction."
)

SCENARIOS: tuple[dict[str, Any], ...] = (
    {
        "id": "legitimate_transfer",
        "title": "Legitimate transfer",
        "narrative": (
            "A registered treasury service requests a modest transfer to an approved destination. "
            "Expect ALLOW, an issued authorization, and a simulated execution."
        ),
        "expected_decision": "ALLOW",
        "signing": "with_authorization",
        "transaction": {
            "service_id": "treasury-agent",
            "operation": "WITHDRAWAL",
            "chain": "eth",
            "asset": "USDC",
            "amount": "1250.50",
            "destination": "0x4e6d3A556e485188E9C9a528bc72c88BD92BD735",
            "request_id": "sim-legitimate-0001",
            "client_reference": "invoice-4471",
        },
    },
    {
        "id": "suspicious_transfer",
        "title": "Suspicious transfer",
        "narrative": (
            "A transfer far above the configured limit, to a destination that is not approved. "
            "Expect BLOCK, no authorization, and a signer refusal."
        ),
        "expected_decision": "BLOCK",
        "signing": "without_authorization",
        "transaction": {
            "service_id": "treasury-agent",
            "operation": "WITHDRAWAL",
            "chain": "eth",
            "asset": "USDC",
            "amount": "480000",
            "destination": "0x9f8A2c4b7e6D1f03aB5C8e2947D6f10B3aE4c5D6",
            "request_id": "sim-suspicious-0001",
            "client_reference": "urgent-request",
        },
    },
    {
        "id": "authorization_bypass",
        "title": "Authorization bypass attempt",
        "narrative": (
            "An application submits a transaction to the signer with no authorization at all, or "
            "with a token minted for different parameters. Expect a refusal in both cases."
        ),
        "expected_decision": "REFUSED",
        "signing": "bypass_attempt",
        "transaction": {
            "service_id": "treasury-agent",
            "operation": "WITHDRAWAL",
            "chain": "eth",
            "asset": "USDC",
            "amount": "900",
            "destination": "0x4e6d3A556e485188E9C9a528bc72c88BD92BD735",
            "request_id": "sim-bypass-0001",
        },
    },
)
