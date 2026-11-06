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

#: A provider/config error on the custody path. Imported at module scope so the
#: handler can classify it without a deferred import on the hot path.
from ..near.outlayer import OutLayerError

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
        self,
        service: GuardService,
        lifecycle: Any = None,
        investigation_store: Any = None,
        near_execution: Any = None,
        tee_provider: Any = None,
        enclave: Any = None,
        custody: Any = None,
    ) -> None:
        self.service = service
        #: The optional durable settlement-investigation store. When set, a
        #: completed investigation is retrievable later, across a restart.
        self.investigation_store = investigation_store
        #: The optional NEAR Intents lifecycle. Built only when the operator has
        #: enabled it and configured a durable store, so a deployment that does
        #: not offer the lifecycle pays nothing and exposes no route.
        self.lifecycle = lifecycle
        #: The optional NEAR execution boundary: the one path that may build a
        #: real transaction, obtain a wallet signature, broadcast it and verify
        #: settlement. Off by default; a deployment that does not opt in exposes
        #: no route and holds no network path to a signing flow.
        self.near_execution = near_execution
        #: The optional real TEE attestation provider. When set, a genuine Intel
        #: TDX quote is fetched from the NEAR AI Cloud gateway and verified
        #: locally against the pinned Intel root, bound to a fresh decision nonce.
        #: Off by default; no TEE protection is ever claimed without it.
        self.tee_provider = tee_provider
        #: The optional enclave signing boundary. When set, a prepared operation
        #: can be signed inside a measured enclave: the boundary provisions a key
        #: only from a verified, measurement-pinned, transaction-bound attestation
        #: and returns a signature that verifies over the exact bytes. With no
        #: signing endpoint configured it reports itself unavailable and refuses,
        #: so hardware execution stays disabled rather than falling back to a
        #: software key.
        self.enclave = enclave
        #: The optional OutLayer custody boundary: the one path that sends an
        #: authorized operation to a TEE-held signing wallet. Off by default; when
        #: set, an operation reaches the provider only after the guard returned
        #: ALLOW, and settlement is verified independently against the NEAR RPC.
        self.custody = custody

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
        if path == "/api/guard/near/agent-demo":
            return self._near_agent_demo()
        if path == "/api/guard/near/execution":
            return self._near_execution_info()
        if path == "/api/guard/near/prompt-injection":
            return self._near_prompt_injection()
        if path == "/api/guard/near/behaviours":
            return self._near_behaviours()
        if path == "/api/guard/near/wallet":
            return self._near_wallet_info()
        if path == "/api/guard/near/access-keys":
            return ApiResponse(200, {"keys": self._near_access_keys()})
        if path == "/api/guard/near/policy-scope":
            return ApiResponse(200, self._near_policy_scope())
        if path == "/api/guard/near/settlement-demo":
            return ApiResponse(200, self._near_settlement_demo())
        if path == "/api/guard/near/tee":
            return self._near_tee_info()
        if path == "/api/guard/near/enclave":
            return self._near_enclave_info()
        if path == "/api/guard/near/custody":
            return self._near_custody_info()
        if path == "/api/guard/near/custody/status":
            return self._near_custody_status()
        if path == "/api/guard/near/tee/attest":
            return self._near_tee_attest(params)
        if path.startswith("/api/guard/near/execution/record/"):
            execution_id = path[len("/api/guard/near/execution/record/") :].strip("/")
            return self._near_execution_record(execution_id)
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

    def _near_prompt_injection(self) -> ApiResponse:
        """Run the prompt-injection demonstration and return its audit trail.

        It runs the real guard controls and the real reference signer against a
        synthetic blocked receiver. Nothing is broadcast. The response is clearly
        labelled as a simulation.
        """
        from ..near.prompt_injection import run_prompt_injection

        audit = run_prompt_injection()
        return ApiResponse(
            200,
            {
                "note": (
                    "Simulated demonstration: a synthetic blocked receiver, the real "
                    "authorization boundary, and a simulated executor that never "
                    "broadcasts. Not a live attack."
                ),
                "audit": audit.to_dict(),
            },
        )

    def _near_behaviours(self) -> ApiResponse:
        """Run the six required agent-authorization behaviours, each labelled."""
        from ..near.prompt_injection import run_all_behaviours

        results = run_all_behaviours()
        return ApiResponse(
            200,
            {
                "note": (
                    "Simulated demonstrations of the six required behaviours: ALLOW, WARN "
                    "(human approval), BLOCK, tamper, replay and fail-safe failure. The "
                    "executor is simulated and never broadcasts."
                ),
                "behaviours": [b.to_dict() for b in results],
                "all_held": all(b.held for b in results),
            },
        )

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

    def _near_agent_demo(self) -> ApiResponse:
        """Run the offline end-to-end agent-payment demonstration.

        One story, two scenarios, through the real authorization boundary, the
        real signer, and the real settlement verifier. The only substitution is
        the network transport: no key is held and nothing reaches a chain. The
        response is labelled a simulation and carries the signer-invocation count
        and the broadcast state, so "the signer was never reached" is provable
        rather than asserted.
        """
        from ..near.agent_demo import run_agent_payment_demo

        result = run_agent_payment_demo()
        return ApiResponse(200, result.to_dict())

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

    def _near_tee_info(self) -> ApiResponse:
        """Describe the TEE attestation capability honestly."""
        if self.tee_provider is None:
            return ApiResponse(
                200,
                {
                    "enabled": False,
                    "note": (
                        "TEE attestation verification is disabled. Enable it with "
                        "TRACESETTLE_TEE_ATTESTATION=1. It fetches a genuine Intel TDX "
                        "quote from the NEAR AI Cloud gateway and verifies it locally; "
                        "no TEE protection is ever claimed without a verified quote."
                    ),
                },
            )
        return ApiResponse(
            200,
            {
                "enabled": True,
                "provider": "near-ai-cloud",
                "endpoint": self.tee_provider.url,
                "verifies": [
                    "Intel TDX quote signature under the quote's attestation key",
                    "PCK certificate chain up to the pinned Intel SGX Root CA",
                    "attestation key bound to the Quoting Enclave report",
                    "report_data binds a fresh decision nonce",
                    "report_data binds the signing address and TLS key",
                    "event-log replay reproduces RTMR0..3",
                ],
                "not_verified": [
                    "PCK certificate revocation status (needs Intel PCS collateral)",
                    "TCB level against Intel PCS collateral",
                ],
                "note": (
                    "The quote is real hardware attestation and is verified locally against "
                    "the pinned Intel root. Revocation and TCB freshness require Intel PCS "
                    "collateral and are not checked here, so they are not claimed."
                ),
            },
        )

    def _near_enclave_info(self) -> ApiResponse:
        """Describe the enclave signing boundary honestly.

        Enclave signing is *not* enabled unless an endpoint is configured; the
        response says so plainly and never claims hardware protection that is not
        present. The report is derived from the configured boundary.
        """
        if self.enclave is None:
            return ApiResponse(
                200,
                {
                    "enabled": False,
                    "note": (
                        "Enclave signing is disabled. Configure TRACESETTLE_ENCLAVE_SIGN_URL "
                        "and TRACESETTLE_ENCLAVE_APPROVED_MEASUREMENT to sign inside a "
                        "measured enclave. No enclave protection is ever claimed without a "
                        "verified, measurement-pinned, transaction-bound attestation."
                    ),
                },
            )
        available = bool(getattr(self.enclave, "available", lambda: False)())
        approved = getattr(self.enclave.measurements, "approved", [])
        return ApiResponse(
            200,
            {
                "enabled": True,
                "available": available,
                "measurements": [m.to_dict() for m in approved],
                "signing_algo": "ed25519",
                "verifies": [
                    "the Intel TDX quote against the pinned Intel root",
                    "the measurement against the operator's approved identity",
                    "the attestation nonce is bound to the exact transaction",
                    "the returned signature over the exact bytes with the provisioned key",
                ],
                "note": (
                    "A key is provisioned only against a verified, measurement-pinned, "
                    "transaction-bound attestation; the host cannot obtain a usable "
                    "signature without it."
                    if available
                    else "No signing endpoint is configured; the boundary refuses to sign."
                ),
            },
        )

    def _near_tee_attest(self, params: dict[str, str]) -> ApiResponse:
        """Fetch and locally verify a genuine TDX attestation bound to a nonce.

        The nonce is supplied by the caller (so the caller controls the binding
        value it will check) or derived from the query fields. A failed
        verification is reported as UNVERIFIABLE, never as protection.
        """
        if self.tee_provider is None:
            return ApiResponse(
                404,
                {
                    "error": "TEE attestation verification is disabled",
                    "enable_with": "TRACESETTLE_TEE_ATTESTATION=1",
                },
            )
        from ..near.attestation import derive_nonce

        supplied = params.get("nonce", "").strip()
        if supplied:
            try:
                nonce = bytes.fromhex(supplied)
            except ValueError:
                return _bad_request("nonce must be hex")
            if len(nonce) != 32:
                return _bad_request("nonce must be 32 bytes (64 hex characters)")
        else:
            nonce = derive_nonce(
                transaction_fingerprint=params.get("transaction_fingerprint", ""),
                policy_revision=params.get("policy_revision", ""),
                operation_id=params.get("operation_id", ""),
            )
        try:
            result = self.tee_provider.attest(nonce)
        except Exception as exc:  # noqa: BLE001 - a provider failure is not an acceptance
            return ApiResponse(
                502,
                {
                    "error": "attestation provider failed",
                    "detail": type(exc).__name__,
                    "verified": False,
                },
            )
        return ApiResponse(200, result.to_dict())

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
        if path == "/api/guard/near/execution/prepare":
            if not self._identity_matches(body, authenticated_service_id):
                return ApiResponse(403, {"error": "service identity does not match the credential"})
            return self._near_execution_prepare(body, authenticated_service_id)
        if path == "/api/guard/near/execution/attest":
            if not self._identity_matches(body, authenticated_service_id):
                return ApiResponse(403, {"error": "service identity does not match the credential"})
            return self._near_execution_attest(body, authenticated_service_id)
        if path == "/api/guard/near/execution/enclave-sign":
            if not self._identity_matches(body, authenticated_service_id):
                return ApiResponse(403, {"error": "service identity does not match the credential"})
            return self._near_execution_enclave_sign(body, authenticated_service_id)
        if path == "/api/guard/near/execution/submit":
            if not self._identity_matches(body, authenticated_service_id):
                return ApiResponse(403, {"error": "service identity does not match the credential"})
            return self._near_execution_submit(body, authenticated_service_id)
        if path == "/api/guard/near/wallet/prepare":
            if not self._identity_matches(body, authenticated_service_id):
                return ApiResponse(403, {"error": "service identity does not match the credential"})
            return self._near_wallet_prepare(body, authenticated_service_id)
        if path == "/api/guard/near/wallet/verify":
            if not self._identity_matches(body, authenticated_service_id):
                return ApiResponse(403, {"error": "service identity does not match the credential"})
            return self._near_wallet_verify(body, authenticated_service_id)
        if path == "/api/guard/near/custody/prepare":
            if not self._identity_matches(body, authenticated_service_id):
                return ApiResponse(403, {"error": "service identity does not match the credential"})
            return self._near_custody_prepare(body, authenticated_service_id)
        if path == "/api/guard/near/custody/execute":
            if not self._identity_matches(body, authenticated_service_id):
                return ApiResponse(403, {"error": "service identity does not match the credential"})
            return self._near_custody_execute(body, authenticated_service_id)
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
        approval = self._near_approval(body)
        if isinstance(approval, ApiResponse):
            return approval
        try:
            decision = self.service.evaluate_agent_transaction(
                transaction,
                policy_read=self._near_policy_read(body),
                access_key=self._near_access_key(body),
                counterparty=self._near_counterparty(body),
                approval=approval,
            )
        except RequestValidationError as exc:
            return _bad_request(str(exc))
        return ApiResponse(
            200,
            decision.to_dict(include_authorization=bool(body.get("return_authorization", False))),
        )

    def _near_counterparty(self, body: Any) -> Any:
        """The counterparty read for this request.

        Read from the configured reader against the *actual* destination, never
        from a client-supplied read (a client could otherwise claim a clean
        counterparty). A client may only ask for the read to be skipped, which
        the wrapper records as a limitation, never as a clean result.
        """
        reader = getattr(self.service, "counterparty_reader", None)
        if reader is None:
            return None
        transaction = body.get("transaction") if isinstance(body, dict) else None
        if not isinstance(transaction, dict):
            return None
        destination = str(transaction.get("destination", "")).strip()
        if not destination:
            return None
        try:
            return reader.read(destination)
        except Exception:  # noqa: BLE001 - a failed read must never be a pass
            from ..near.counterparty import CounterpartyOutcome, CounterpartyRead

            return CounterpartyRead(
                account_id=destination,
                chain=str(getattr(reader, "chain", "")),
                outcome=CounterpartyOutcome.UNKNOWN,
                limitations=(
                    "the counterparty reader raised while reading the destination; the "
                    "counterparty could not be checked",
                ),
            )

    def _near_approval(self, body: Any) -> Any:
        """The human approval presented with this request, or ``None``.

        A malformed approval is refused rather than ignored, so an agent cannot
        smuggle a bad approval past the route.
        """
        from ..near.approval import Approval

        raw = body.get("approval") if isinstance(body, dict) else None
        if raw is None:
            return None
        if not isinstance(raw, dict):
            return _bad_request("field 'approval' must be a JSON object")
        try:
            return Approval.from_dict(raw)
        except (ValueError, TypeError) as exc:
            return _bad_request(f"field 'approval': {exc}")

    # -- NEAR execution boundary -------------------------------------------

    def _require_near_execution(self) -> ApiResponse | None:
        if self.near_execution is None:
            return ApiResponse(
                404,
                {
                    "error": "the NEAR execution boundary is not enabled",
                    "hint": "set TRACESETTLE_NEAR_EXECUTION=1 and configure the network",
                },
            )
        return None

    def _near_execution_info(self) -> ApiResponse:
        """Describe the execution boundary, or report that it is disabled."""
        if self.near_execution is None:
            return ApiResponse(
                200,
                {
                    "enabled": False,
                    "note": (
                        "The NEAR execution boundary is disabled. Enable it with "
                        "TRACESETTLE_NEAR_EXECUTION=1. It never holds a key: a "
                        "prepared transaction is signed by the caller's wallet."
                    ),
                },
            )
        config = self.near_execution.config
        tee_authorizer = getattr(self.near_execution, "tee_authorizer", None)
        return ApiResponse(
            200,
            {
                "enabled": True,
                "network": config.to_dict(),
                "signs": False,
                "broadcasts": True,
                "tee_gate": {
                    "enabled": tee_authorizer is not None,
                    "required": bool(getattr(self.near_execution, "tee_required", False)),
                    "measurement_pinned": bool(
                        getattr(tee_authorizer, "expected_measurement", "")
                    ),
                    "note": (
                        "When required, a verified Intel TDX attestation bound to the "
                        "transaction digest and decision nonce must exist before the "
                        "boundary will accept a signature. The server holds no key."
                        if tee_authorizer is not None
                        else "No TEE gate: enable TRACESETTLE_NEAR_TEE_REQUIRED=1 to make a "
                        "verified attestation a precondition of signing."
                    ),
                },
                "note": (
                    "TraceSettle builds the transaction and independently verifies "
                    "settlement. It never holds a private key: the wallet signs."
                ),
            },
        )

    def _near_execution_record(self, execution_id: str) -> ApiResponse:
        """Return the durable execution record: the lifecycle and its evidence.

        The record is the inspectable proof of the lifecycle - the authorization,
        the TEE binding, and the settlement - so a caller can see exactly which
        gate a transaction reached and what evidence backed it.
        """
        if self.near_execution is None:
            return ApiResponse(200, {"enabled": False, "record": None})
        authorizer = getattr(self.near_execution, "tee_authorizer", None)
        if authorizer is None:
            return ApiResponse(
                200,
                {
                    "enabled": False,
                    "record": None,
                    "note": (
                        "No TEE gate is enabled, so no execution records are kept. "
                        "Enable TRACESETTLE_NEAR_TEE_REQUIRED=1."
                    ),
                },
            )
        record = authorizer.get(execution_id)
        if record is None:
            return ApiResponse(404, {"error": "unknown execution id"})
        return ApiResponse(200, {"enabled": True, "record": record.to_dict()})

    def _near_execution_owner(self, authenticated_service_id: str | None) -> str:
        """The owner a prepared operation belongs to.

        The authenticated identity when service authentication is enabled, and a
        single ``local`` owner otherwise. It is deliberately **not** taken from a
        body field: prepare and submit must agree on the owner without the client
        supplying it, and one service must never reach another's prepared
        operation.
        """
        return authenticated_service_id if authenticated_service_id is not None else "local"

    def _near_execution_prepare(self, body: Any, authenticated_service_id: str | None) -> ApiResponse:
        """Build a real transaction and evaluate it with the operator policy.

        Nothing is signed or broadcast here. On ALLOW the prepared operation is
        stored (owner-scoped, single-use) and its id returned; the caller signs
        ``transaction`` with their wallet and posts the signature to
        ``/submit``. On any other outcome no authorization is issued and there is
        nothing to sign.
        """
        refused = self._require_near_execution()
        if refused is not None:
            return refused
        if not isinstance(body, dict):
            return _bad_request("request body must be a JSON object")
        required = ("service_id", "account_id", "public_key", "receiver_id", "asset", "amount")
        missing = [f for f in required if not str(body.get(f, "")).strip()]
        if missing:
            return _bad_request("missing required field(s): " + ", ".join(missing))
        from ..near.execution import ExecutionError

        try:
            prepared = self.near_execution.prepare(
                service_id=str(body["service_id"]),
                account_id=str(body["account_id"]),
                public_key=str(body["public_key"]),
                receiver_id=str(body["receiver_id"]),
                asset_identifier=str(body["asset"]),
                amount_human=str(body["amount"]),
                network=body.get("network"),
                request_id=body.get("request_id"),
                idempotency_key=body.get("idempotency_key"),
            )
        except ExecutionError as exc:
            return ApiResponse(422, {"error": str(exc)})
        payload = prepared.to_dict()
        if prepared.authorized:
            owner = self._near_execution_owner(authenticated_service_id)
            prepare_id = self.near_execution_store().store(prepared, owner)
            payload["prepare_id"] = prepare_id
            payload["expires_in_seconds"] = 90
        return ApiResponse(200, payload)

    def _near_execution_attest(self, body: Any, authenticated_service_id: str | None) -> ApiResponse:
        """Fetch a genuine TEE attestation and bind it to a prepared transaction.

        This is the step that makes the TEE participate in execution: once an
        attestation is bound, the boundary will accept a signature; without it,
        and with the gate enabled, it refuses. The attestation is fetched from the
        provider configured server-side - never a client-supplied one - and the
        nonce is derived from the execution record, so an attestation obtained for
        one transaction cannot be replayed for another.
        """
        refused = self._require_near_execution()
        if refused is not None:
            return refused
        if not isinstance(body, dict):
            return _bad_request("request body must be a JSON object")
        prepare_id = str(body.get("prepare_id", "")).strip()
        if not prepare_id:
            return _bad_request("field 'prepare_id' is required")
        boundary = self.near_execution
        if boundary.tee_authorizer is None:
            return ApiResponse(
                409,
                {
                    "error": (
                        "the TEE execution gate is not enabled on this deployment; "
                        "no attestation can be bound"
                    )
                },
            )
        owner = self._near_execution_owner(authenticated_service_id)
        prepared = self.near_execution_store().peek(prepare_id, owner)
        if prepared is None:
            return ApiResponse(404, {"error": "unknown or expired prepare_id"})
        if not prepared.authorized:
            return ApiResponse(422, {"error": "the operation was not authorized"})
        from ..near.execution import ExecutionError

        try:
            record = boundary.verify_tee_attestation(prepared)
        except ExecutionError as exc:
            return ApiResponse(422, {"error": str(exc)})
        except Exception as exc:  # noqa: BLE001 - a failed verification is a refusal
            return ApiResponse(422, {"error": f"TEE attestation failed: {type(exc).__name__}"})
        return ApiResponse(
            200,
            {
                "prepare_id": prepare_id,
                "execution_id": prepared.execution_id,
                "tee_verified": record.tee_verified,
                "state": record.state,
                "tee_binding": record.tee_binding.to_dict() if record.tee_binding else None,
            },
        )

    def _near_execution_submit(self, body: Any, authenticated_service_id: str | None) -> ApiResponse:
        """Accept a wallet signature, broadcast, and verify settlement.

        The prepared operation is looked up from the server-side store (never
        rebuilt from the request), so the bytes that are broadcast are provably
        the bytes that were prepared and authorized. The authorization binding is
        re-validated against the stored transaction and the single-use nonce is
        consumed; the signature must verify against the transaction hash.
        """
        refused = self._require_near_execution()
        if refused is not None:
            return refused
        if not isinstance(body, dict):
            return _bad_request("request body must be a JSON object")
        prepare_id = str(body.get("prepare_id", "")).strip()
        signature = str(body.get("signature", "")).strip()
        if not prepare_id or not signature:
            return _bad_request("fields 'prepare_id' and 'signature' are required")
        owner = self._near_execution_owner(authenticated_service_id)
        prepared = self.near_execution_store().take(prepare_id, owner)
        if prepared is None:
            return ApiResponse(404, {"error": "unknown or expired prepare_id"})
        from ..near.execution import ExecutionError

        pipeline = getattr(self.near_execution, "pipeline", None)
        if pipeline is not None:
            # The durable path: the submission is recorded before it is sent, so
            # an unknown outcome is resolved from the chain rather than retried,
            # and the execution is polled to a final status before verifying.
            idempotency_key = str(body.get("idempotency_key", "")).strip()
            try:
                executed = pipeline.submit_signed(
                    prepared, signature, idempotency_key=idempotency_key
                )
            except ExecutionError as exc:
                return ApiResponse(422, {"error": str(exc)})
            return ApiResponse(200, executed.to_dict())

        try:
            executed = self.near_execution.broadcast(prepared, signature)
        except ExecutionError as exc:
            return ApiResponse(422, {"error": str(exc)})
        return ApiResponse(200, executed.to_dict())

    def _near_execution_enclave_sign(self, body: Any, authenticated_service_id: str | None) -> ApiResponse:
        """Sign a prepared operation inside a verified enclave.

        The prepared operation is looked up from the server-side store (never
        rebuilt from the request), so the bytes signed are the bytes that were
        prepared and authorized. The enclave boundary provisions a key only
        against a verified, measurement-pinned attestation bound to this exact
        transaction, and the returned signature is verified over the exact
        transaction-hash bytes. Nothing is broadcast here; the caller submits the
        returned signature through ``/api/guard/near/execution/submit``.
        """
        refused = self._require_near_execution()
        if refused is not None:
            return refused
        if self.enclave is None:
            return ApiResponse(
                409,
                {
                    "error": (
                        "enclave signing is not configured; set TRACESETTLE_ENCLAVE_SIGN_URL "
                        "and TRACESETTLE_ENCLAVE_APPROVED_MEASUREMENT, or sign with a wallet"
                    )
                },
            )
        if not isinstance(body, dict):
            return _bad_request("request body must be a JSON object")
        prepare_id = str(body.get("prepare_id", "")).strip()
        if not prepare_id:
            return _bad_request("field 'prepare_id' is required")
        owner = self._near_execution_owner(authenticated_service_id)
        prepared = self.near_execution_store().peek(prepare_id, owner)
        if prepared is None:
            return ApiResponse(404, {"error": "unknown or expired prepare_id"})

        from ..near.enclave import (
            EnclaveError,
            EnclaveTransactionSigner,
            ProvisioningRequest,
        )

        import base64

        transaction = prepared.transaction
        request = ProvisioningRequest(
            key_id=str(body.get("key_id", "")).strip() or "enclave-signing-key",
            purpose="near-execution",
            execution_id=prepared.execution_id or transaction.tx_hash,
            transaction_digest=transaction.tx_hash_bytes.hex(),
            decision_nonce=prepared.tee_nonce or transaction.tx_hash,
            policy_version="v1",
        )
        try:
            key = self.enclave.provision(request)
            signer = EnclaveTransactionSigner(
                boundary=self.enclave,
                key=key,
                request=request,
                account_id=transaction.signer_id,
                network=transaction.network,
            )
            signature = signer.sign(transaction.tx_hash_bytes)
        except EnclaveError as exc:
            return ApiResponse(422, {"error": str(exc)})

        return ApiResponse(
            200,
            {
                "prepare_id": prepare_id,
                "tx_hash": transaction.tx_hash,
                "public_key": signer.public_key,
                "signing_algo": key.signing_algo,
                "measurement": key.measurement_name,
                "signature": base64.b64encode(signature).decode("ascii"),
                "note": (
                    "the signature was produced inside the measured enclave and verified "
                    "over the exact transaction bytes; submit it to broadcast"
                ),
            },
        )

    def near_execution_store(self) -> Any:
        store = getattr(self, "_near_execution_store", None)
        if store is None:
            from ..near.execution import PreparedOperationStore

            store = PreparedOperationStore()
            self._near_execution_store = store
        return store

    # -- NEAR OutLayer custody flow (a TEE-held wallet signs) ---------------

    def _require_custody(self) -> ApiResponse | None:
        if self.custody is None:
            return ApiResponse(
                404,
                {
                    "error": "the OutLayer custody boundary is not enabled",
                    "hint": (
                        "set TRACESETTLE_OUTLAYER_ENABLED=1, TRACESETTLE_OUTLAYER_API_KEY and "
                        "TRACESETTLE_NEAR_EXECUTION=1"
                    ),
                },
            )
        return None

    def _near_custody_info(self) -> ApiResponse:
        """Describe the custody boundary. Off unless the operator enabled it.

        No provider call is made here, so a status page never implies a live
        connection it has not opened; ``/custody/status`` is the explicit probe.
        """
        if self.custody is None:
            return ApiResponse(
                200,
                {
                    "enabled": False,
                    "mode": "outlayer-custody",
                    "note": (
                        "The OutLayer custody boundary is disabled. Enable it with "
                        "TRACESETTLE_OUTLAYER_ENABLED=1 and a provider API key. It is the "
                        "only path that sends an authorized operation to a TEE-held signing "
                        "wallet."
                    ),
                },
            )
        return ApiResponse(200, {"enabled": True, **self.custody.info()})

    def _near_custody_status(self) -> ApiResponse:
        """Probe the provider: reachability, wallet identity, balance, policy.

        Every field is real evidence or an explicit error; nothing is asserted
        that was not observed. The provider's own policy and the register
        contract's approved measurements are reported as *evidence*, never as
        TraceSettle's authorization.
        """
        refused = self._require_custody()
        if refused is not None:
            return refused
        return ApiResponse(200, self.custody.provider_status())

    def _near_custody_prepare(self, body: Any, authenticated_service_id: str | None) -> ApiResponse:
        """Build and evaluate a custody transfer. Never sends anything."""
        refused = self._require_custody()
        if refused is not None:
            return refused
        if not isinstance(body, dict):
            return _bad_request("request body must be a JSON object")
        destination = str(body.get("destination", "")).strip()
        amount = str(body.get("amount", "")).strip()
        service_id = str(body.get("service_id", "")).strip()
        if not destination or not amount or not service_id:
            return _bad_request("fields 'service_id', 'destination' and 'amount' are required")
        from ..near.outlayer_execution import CustodyError

        try:
            prepared = self.custody.prepare(
                service_id=service_id,
                destination=destination,
                amount_human=amount,
                request_id=str(body.get("request_id", "")).strip() or None,
                idempotency_key=str(body.get("idempotency_key", "")).strip() or None,
            )
        except CustodyError as exc:
            return ApiResponse(422, {"error": str(exc)})
        except OutLayerError as exc:  # provider/config error, never worked around
            return ApiResponse(503, {"error": str(exc)})
        owner = self._near_execution_owner(authenticated_service_id)
        prepare_id = self.near_custody_store().store(prepared, owner)
        return ApiResponse(
            200,
            {
                "prepare_id": prepare_id,
                "operation": "custody-transfer",
                "prepared": prepared.to_dict(),
                "note": (
                    "the operation was evaluated; it reaches the provider only through "
                    "/custody/execute and only when the decision is ALLOW"
                ),
            },
        )

    def _near_custody_execute(self, body: Any, authenticated_service_id: str | None) -> ApiResponse:
        """Send the authorized operation to the custody provider and verify it.

        The prepared operation is looked up from the server-side store, never
        rebuilt from the request, so the bytes sent are provably the bytes that
        were authorized. The authorization binding is re-validated against the
        operation and the single-use nonce is consumed before the send.
        """
        refused = self._require_custody()
        if refused is not None:
            return refused
        if not isinstance(body, dict):
            return _bad_request("request body must be a JSON object")
        prepare_id = str(body.get("prepare_id", "")).strip()
        if not prepare_id:
            return _bad_request("field 'prepare_id' is required")
        owner = self._near_execution_owner(authenticated_service_id)
        prepared = self.near_custody_store().take(prepare_id, owner)
        if prepared is None:
            return ApiResponse(404, {"error": "unknown or expired prepare_id"})
        from ..near.outlayer_execution import CustodyError

        try:
            execution = self.custody.execute(prepared)
        except CustodyError as exc:
            return ApiResponse(422, {"error": str(exc)})
        except OutLayerError as exc:
            return ApiResponse(503, {"error": str(exc)})
        # Record the independent settlement outcome on the hash-chained audit log
        # so the evidence survives the request. The stored fields are public
        # on-chain identifiers and the derived state only - never a secret.
        self.service.audit.append(
            event_type="CUSTODY_EXECUTION",
            actor=owner,
            outcome=execution.verification.state.value,
            detail=execution.verification.note,
            service_id=prepared.service_id,
            authorization_id=execution.authorization_id,
            extra={
                "tx_hash": execution.tx_hash,
                "provider_state": execution.provider.state.value,
                "provider_claimed_success": execution.provider_claimed_success,
                "settlement_verified": execution.settlement_verified,
                "evidence_state": execution.evidence_state.value,
                "tee_attested": bool(
                    execution.attestation is not None and execution.attestation.tee_attested
                ),
                "network": prepared.network.value,
                "amount_near": str(prepared.amount_human),
                "destination": prepared.destination,
                "checks": [{"name": c.name, "ok": c.ok} for c in execution.verification.checks],
            },
        )
        return ApiResponse(200, execution.to_dict())

    def near_custody_store(self) -> Any:
        store = getattr(self, "_near_custody_store", None)
        if store is None:
            from ..near.execution import PreparedOperationStore

            store = PreparedOperationStore()
            self._near_custody_store = store
        return store

    # -- NEAR wallet-mediated flow (the connected wallet signs and sends) ---

    def _near_wallet_info(self) -> ApiResponse:
        """Describe the wallet flow. Off unless the execution boundary is on."""
        if self.near_execution is None:
            return ApiResponse(
                200,
                {
                    "enabled": False,
                    "mode": "wallet",
                    "note": (
                        "The NEAR wallet flow is disabled. Enable it with "
                        "TRACESETTLE_NEAR_EXECUTION=1. The connected wallet signs "
                        "and sends; this server holds no key."
                    ),
                },
            )
        info = self.near_execution.wallet_execution_info()
        info["network_config"] = self.near_execution.config.to_dict()
        return ApiResponse(200, info)

    def _near_wallet_prepare(self, body: Any, authenticated_service_id: str | None) -> ApiResponse:
        """Authorize a wallet operation and return the request the wallet signs.

        TraceSettle does not build or broadcast the transaction here: it evaluates
        the real intent against the operator policy and, on ALLOW, returns a
        transaction-bound authorization plus the exact wallet request. The wallet
        (the user's browser extension/mobile wallet) signs and sends it.
        """
        refused = self._require_near_execution()
        if refused is not None:
            return refused
        if not isinstance(body, dict):
            return _bad_request("request body must be a JSON object")
        required = ("service_id", "account_id", "receiver_id", "asset", "amount")
        missing = [f for f in required if not str(body.get(f, "")).strip()]
        if missing:
            return _bad_request("missing required field(s): " + ", ".join(missing))
        from ..near.execution import ExecutionError

        try:
            prepared = self.near_execution.prepare_wallet_operation(
                service_id=str(body["service_id"]),
                account_id=str(body["account_id"]),
                receiver_id=str(body["receiver_id"]),
                asset_identifier=str(body["asset"]),
                amount_human=str(body["amount"]),
                network=body.get("network"),
                memo=body.get("memo"),
                request_id=body.get("request_id"),
                idempotency_key=body.get("idempotency_key"),
            )
        except ExecutionError as exc:
            return ApiResponse(422, {"error": str(exc)})
        payload = prepared.to_dict()
        if prepared.authorized:
            owner = self._near_execution_owner(authenticated_service_id)
            prepare_id = self.near_wallet_store().store(prepared, owner)
            payload["prepare_id"] = prepare_id
            payload["expires_in_seconds"] = 300
        return ApiResponse(200, payload)

    def _near_wallet_verify(self, body: Any, authenticated_service_id: str | None) -> ApiResponse:
        """Verify a wallet-submitted transaction against the authorized intent.

        The prepared operation is looked up server-side (never rebuilt from the
        request), the single-use authorization nonce is consumed, and the on-chain
        record is checked against the intent. The outcome is the independent
        settlement state, not the wallet's "success".
        """
        refused = self._require_near_execution()
        if refused is not None:
            return refused
        if not isinstance(body, dict):
            return _bad_request("request body must be a JSON object")
        prepare_id = str(body.get("prepare_id", "")).strip()
        tx_hash = str(body.get("tx_hash", "")).strip()
        if not prepare_id or not tx_hash:
            return _bad_request("fields 'prepare_id' and 'tx_hash' are required")
        owner = self._near_execution_owner(authenticated_service_id)
        prepared = self.near_wallet_store().take(prepare_id, owner)
        if prepared is None:
            return ApiResponse(404, {"error": "unknown or expired prepare_id"})
        from ..near.execution import ExecutionError

        try:
            verification = self.near_execution.verify_wallet_submission(prepared, tx_hash)
        except ExecutionError as exc:
            return ApiResponse(422, {"error": str(exc)})
        # Record the independent settlement outcome on the hash-chained audit log
        # so the evidence survives the request. The stored fields are public
        # on-chain identifiers and the derived state only - never a secret.
        self.service.audit.append(
            event_type="SETTLEMENT_VERIFICATION",
            actor=self._near_execution_owner(authenticated_service_id),
            outcome=verification.state.value,
            detail=verification.note,
            service_id=prepared.decision.request.service_id if prepared.decision.request else None,
            authorization_id=prepared.authorization_id,
            extra={
                "tx_hash": tx_hash,
                "prepare_id": prepare_id,
                "network": prepared.network.value,
                "operation": prepared.operation,
                "asset": prepared.asset.identifier,
                "amount_human": str(prepared.amount_human),
                "destination": prepared.destination,
                "checks": [{"name": c.name, "ok": c.ok} for c in verification.checks],
            },
        )
        return ApiResponse(
            200,
            {
                "tx_hash": tx_hash,
                "account_id": prepared.account_id,
                "operation": prepared.operation,
                "asset": prepared.asset.to_dict(),
                "amount_human": str(prepared.amount_human),
                "destination": prepared.destination,
                "verification": verification.to_dict(),
            },
        )

    def near_wallet_store(self) -> Any:
        store = getattr(self, "_near_wallet_store", None)
        if store is None:
            from ..near.execution import PreparedWalletStore

            store = PreparedWalletStore()
            self._near_wallet_store = store
        return store

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
                expected_host=config.NEAR_AGENT_API_EXPECTED_HOST,
                expected_agent_id=config.NEAR_AGENT_ID,
                max_age_seconds=config.NEAR_AGENT_POLICY_MAX_AGE_SECONDS,
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
