"""The complete NEAR Intents transaction lifecycle, wired to the real product.

This module connects the two product pillars over one transaction:

    Identity -> Intent -> Policy -> Authorization -> User Approval ->
    Execution Boundary -> Transaction Evidence -> Independent Settlement
    Investigation -> Verifiable Report

It is the seam the application uses. It does **not** re-implement the guard, the
policy reader, the access-key analysis, or the settlement engine; it calls them.
What it adds is the orchestration, the durable record, and the honest state
transitions between them.

Nothing here signs, broadcasts, or moves funds. The only action that moves money
is the user funding the quote's deposit address from their own wallet, which is a
step this product shows and explains but never performs and never holds a key for.
A live quote's deposit address is issued by the provider, not by this code.

Every stage is explicit about what is evidenced:

* ``quote``       — a provider quote, requested server-side after the policy and
                    guard checks; a ``dry`` quote issues no deposit address.
* ``authorize``   — the guard's decision on the *actual* parameters. Only
                    ``ALLOW`` issues a transaction-bound authorization.
* ``deposit``     — the user's own wallet transaction hash is recorded; the
                    optional ``/v0/deposit/submit`` notification is sent.
* ``status``      — the provider status is read and mapped to a lifecycle label;
                    a provider ``SUCCESS`` never becomes ``SETTLEMENT_VERIFIED``.
* ``assurance``   — the deterministic engine over collected on-chain evidence is
                    the only thing that can verify settlement.

Failure is never hidden: a provider error is surfaced with its source status, and
a guard refusal never reaches the signer.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass
from typing import Any

from . import intents as _intents
from .agent_wrapper import AgentAuthorizationWrapper, AgentTransaction, WrapperOutcome
from .policy import PolicyRead, PolicyScope
from .settlement import NearSettlementAssurance, settlement_assurance_from_result


def _utc_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class LifecycleError(ValueError):
    """A lifecycle step could not proceed, with a client-safe message."""


@dataclass(frozen=True)
class LifecycleStep:
    """One recorded step of the lifecycle, for the timeline and the audit."""

    name: str
    label: str
    ok: bool
    detail: str
    at: str

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "label": self.label, "ok": self.ok, "detail": self.detail, "at": self.at}


class NearIntentsLifecycle:
    """Orchestrates one NEAR Intents transaction across the real product.

    The class is stateless apart from its injected collaborators, so it is easy
    to test: the guard service, the HTTP client, the policy reader and the store
    are all supplied, not created here.
    """

    def __init__(
        self,
        *,
        guard_service: Any,
        http_client: Any,
        store: Any,
    ) -> None:
        self._guard = guard_service
        self._http = http_client
        self._store = store

    # -- assets -------------------------------------------------------------

    def assets(self) -> dict[str, Any]:
        """The provider's supported-asset list (``GET /v0/tokens``)."""
        status, assets, message = _intents.fetch_tokens(self._http)
        return {
            "ok": status.value == "OK",
            "source_status": status.value,
            "message": message,
            "assets": [a.to_dict() for a in assets],
        }

    # -- step 1: create the intent, resolve policy, evaluate the guard -------

    def create_and_authorize(
        self,
        *,
        owner: str,
        payload: dict[str, Any],
        policy_read: PolicyRead | None,
        access_key: Any,
        created_at: str | None = None,
    ) -> dict[str, Any]:
        """Create the intent and run the pre-execution boundary.

        The provider is **not** called here. This step establishes the identity,
        resolves the server-side policy, evaluates the guard, and records the
        decision. Only a subsequent explicit ``quote`` step talks to the
        provider, and only if the decision permits it.
        """
        created_at = created_at or _utc_now()
        # ``recipient`` is the Intents destination; the guard calls the same field
        # ``destination``. Accept either so a caller can use one vocabulary.
        normalized = dict(payload)
        if not normalized.get("recipient") and normalized.get("destination"):
            normalized["recipient"] = normalized["destination"]
        if not normalized.get("refund_to"):
            normalized["refund_to"] = normalized.get("recipient") or normalized.get("destination")
        try:
            quote_request = _intents.QuoteRequest.from_payload(normalized, default_dry=True)
        except _intents.QuoteValidationError as exc:
            raise LifecycleError(str(exc)) from exc

        service_id = str(payload.get("service_id") or owner)
        operation = str(payload.get("operation") or "SWAP")
        scope_raw = str(payload.get("scope") or "INTENTS").strip().upper()
        try:
            scope = PolicyScope(scope_raw)
        except ValueError as exc:
            raise LifecycleError(
                "field 'scope' must be one of INTENTS, NATIVE_NEAR, NATIVE_EVM, NATIVE_SOLANA"
            ) from exc

        # The guard policy is written in human units (USDC, not 6-decimal base
        # units), so the provider base-unit amount is scaled exactly. A mis-scaled
        # amount would corrupt every limit check, so an unknown asset with no
        # explicit ``asset_decimals`` is refused rather than guessed.
        guard_asset = str(payload.get("asset") or payload.get("asset_symbol") or "USDC")
        decimals = payload.get("asset_decimals")
        try:
            guard_amount = _intents.human_amount(
                quote_request.amount,
                symbol=guard_asset,
                decimals=(int(decimals) if decimals is not None else None),
            )
        except (_intents.QuoteValidationError, TypeError, ValueError) as exc:
            raise LifecycleError(str(exc)) from exc

        transaction = AgentTransaction(
            service_id=service_id,
            operation=operation,
            chain=str(payload.get("chain") or _chain_of(quote_request.origin_asset)),
            asset=guard_asset,
            amount=guard_amount,
            destination=quote_request.recipient,
            scope=scope,
            policy_action=(str(payload["policy_action"]) if payload.get("policy_action") else None),
            request_id=(str(payload["request_id"]) if payload.get("request_id") else None),
            idempotency_key=(
                str(payload["idempotency_key"]) if payload.get("idempotency_key") else None
            ),
            client_reference=(
                str(payload["client_reference"]) if payload.get("client_reference") else None
            ),
            receiver_id=(str(payload["receiver_id"]) if payload.get("receiver_id") else None),
            method_name=(str(payload["method_name"]) if payload.get("method_name") else None),
            transfers_near=bool(payload.get("transfers_near", False)),
            simulated=True,
            asserted_approval_fields=tuple(
                str(k)
                for k, v in payload.items()
                if str(k).strip().lower() in {"approved", "skip_checks", "authorized", "override"}
                and v not in (None, False, 0, "", [], {})
            ),
            metadata={"asset_id": quote_request.origin_asset},
        )
        wrapper = AgentAuthorizationWrapper(
            self._guard, policy_read=policy_read, access_key=access_key
        )
        decision = wrapper.evaluate(transaction)

        record, created = self._store.create(
            owner=owner,
            state="AUTHORIZATION_REQUIRED" if decision.outcome is WrapperOutcome.REQUIRE_APPROVAL else decision.outcome.value,
            created_at=created_at,
            idempotency_key=transaction.idempotency_key,
            origin_asset=quote_request.origin_asset,
            destination_asset=quote_request.destination_asset,
            amount=quote_request.amount,
            recipient=quote_request.recipient,
            refund_to=quote_request.refund_to,
            swap_type=quote_request.swap_type,
            slippage_tolerance=quote_request.slippage_tolerance,
            decision=decision.to_dict(include_authorization=True),
            authorization_id=_authorization_id(decision),
        )
        step = LifecycleStep(
            name="authorize",
            label="AUTHORIZATION_GRANTED" if decision.permits_signing else decision.outcome.value,
            ok=decision.outcome is WrapperOutcome.ALLOW,
            detail=decision.summary,
            at=created_at,
        )
        self._store.append_event(
            record.intent_id, owner=owner, at=created_at, kind="DECISION", detail=decision.to_dict()
        )
        return {
            "intent_id": record.intent_id,
            "created": created,
            "state": record.state,
            "decision": decision.to_dict(include_authorization=True),
            "permits_signing": decision.permits_signing,
            "step": step.to_dict(),
        }

    # -- step 2: request the quote (server-side, after the boundary) ---------

    def request_quote(
        self,
        *,
        owner: str,
        intent_id: str,
        dry: bool = False,
        at: str | None = None,
    ) -> dict[str, Any]:
        """Request a quote for an intent the guard has authorized.

        The policy and guard decision were made in :meth:`create_and_authorize`;
        this step refuses to request a **live** (fundable) quote unless the stored
        decision permits signing, so a blocked intent can never obtain a deposit
        address. A ``dry`` quote is always allowed: it moves nothing and issues no
        deposit address.
        """
        at = at or _utc_now()
        record = self._store.get(intent_id, owner=owner)
        if record is None:
            raise LifecycleError("no such intent for this owner")

        decision = record.decision or {}
        permits = bool(decision.get("permits_signing"))
        if not dry and not permits:
            raise LifecycleError(
                "refusing a live quote: the stored decision does not permit signing "
                f"(outcome {decision.get('outcome')})"
            )

        try:
            request = _intents.QuoteRequest.from_payload(
                {
                    "origin_asset": record.origin_asset,
                    "destination_asset": record.destination_asset,
                    "amount": record.amount,
                    "recipient": record.recipient,
                    "refund_to": record.refund_to,
                    "swap_type": record.swap_type,
                    "slippage_tolerance": record.slippage_tolerance,
                    "dry": dry,
                }
            )
        except _intents.QuoteValidationError as exc:
            raise LifecycleError(str(exc)) from exc

        outcome = _intents.request_quote(self._http, request)
        if not outcome.ok:
            self._store.append_event(
                intent_id, owner=owner, at=at, kind="QUOTE_FAILED",
                detail={"source_status": outcome.source_status.value, "message": outcome.message},
            )
            return {
                "ok": False,
                "intent_id": intent_id,
                "source_status": outcome.source_status.value,
                "message": outcome.message,
                "quote": None,
            }

        quote = outcome.quote
        state = "DEPOSIT_ADDRESS_ISSUED" if (quote and quote.deposit_address) else "QUOTE_CREATED"
        self._store.update(
            intent_id,
            owner=owner,
            updated_at=at,
            expect_state=state,
            quote=outcome.to_dict(),
            # A fresh quote clears any prior approval: approval is bound to the
            # exact quote the user reviewed, so a re-quote must be re-approved.
            quote_approved_at=None,
            deposit_address=quote.deposit_address if quote else None,
            deposit_memo=quote.deposit_memo if quote else None,
        )
        self._store.append_event(
            intent_id, owner=owner, at=at, kind="QUOTE", detail=outcome.to_dict()
        )
        expiry = _intents.quote_expiry(quote)
        return {
            "ok": True,
            "intent_id": intent_id,
            "state": state,
            "deposit_address": quote.deposit_address if quote else None,
            "deposit_memo": quote.deposit_memo if quote else None,
            "quote": quote.to_dict() if quote else None,
            "expiry": expiry,
            "dry": dry,
        }

    # -- step 2b: the user explicitly approves (or rejects) the quote --------

    def approve_quote(
        self,
        *,
        owner: str,
        intent_id: str,
        approve: bool,
        at: str | None = None,
    ) -> dict[str, Any]:
        """Record the user's explicit decision on a live quote.

        Approval is a **user** action, recorded separately from the guard's
        authorization: the guard decides whether the transaction is permitted,
        the user decides whether to proceed with *this* quote. Approval requires
        a live (fundable) quote that is still unexpired, so a stale quote can
        never be approved. Approval does not fund anything — it only marks the
        quote the user is willing to fund from their own wallet.
        """
        at = at or _utc_now()
        record = self._store.get(intent_id, owner=owner)
        if record is None:
            raise LifecycleError("no such intent for this owner")
        if not record.deposit_address:
            raise LifecycleError("there is no live quote to approve; request a live quote first")
        if not record.decision or not record.decision.get("permits_signing"):
            raise LifecycleError("the stored decision does not permit signing, so no quote may be approved")

        quote = _intents.QuoteFields.from_dict((record.quote or {}).get("quote"))
        expiry = _intents.quote_expiry(quote)
        if approve and not expiry["usable"]:
            raise LifecycleError(f"the quote cannot be approved: {expiry['detail']}")

        if approve:
            self._store.update(
                intent_id, owner=owner, updated_at=at,
                expect_state="QUOTE_APPROVED", quote_approved_at=at,
            )
            label = "QUOTE_APPROVED"
        else:
            self._store.update(
                intent_id, owner=owner, updated_at=at,
                expect_state="QUOTE_REJECTED", quote_approved_at=None,
            )
            label = "QUOTE_REJECTED"
        self._store.append_event(
            intent_id, owner=owner, at=at, kind=label,
            detail={"approved": approve, "expiry_reason": expiry["reason"]},
        )
        return {
            "ok": True,
            "intent_id": intent_id,
            "state": label,
            "approved": approve,
            "quote_approved_at": at if approve else None,
            "expiry": expiry,
        }

    # -- step 3: record the user's deposit, notify the provider --------------

    def record_deposit(
        self,
        *,
        owner: str,
        intent_id: str,
        deposit_tx_hash: str,
        near_sender_account: str | None = None,
        at: str | None = None,
    ) -> dict[str, Any]:
        """Record the user's own deposit transaction hash and notify the provider.

        The hash is supplied by the user's wallet. This product never submits the
        on-chain transaction; it records the hash and sends the *optional*
        documented notification so the provider can pre-verify the deposit.
        """
        at = at or _utc_now()
        record = self._store.get(intent_id, owner=owner)
        if record is None:
            raise LifecycleError("no such intent for this owner")
        if not record.deposit_address:
            raise LifecycleError("this intent has no deposit address yet; request a live quote first")
        if not record.quote_approved_at:
            raise LifecycleError(
                "the quote has not been approved; approve the live quote before recording a deposit"
            )
        quote = _intents.QuoteFields.from_dict((record.quote or {}).get("quote"))
        expiry = _intents.quote_expiry(quote)
        if not expiry["usable"]:
            raise LifecycleError(
                f"the quote is no longer usable ({expiry['reason']}); request a fresh live quote before "
                "recording a deposit against this address"
            )
        if not isinstance(deposit_tx_hash, str) or not deposit_tx_hash.strip():
            raise LifecycleError("field 'deposit_tx_hash' must be a non-empty string")
        if len(deposit_tx_hash) > 200 or any(ord(c) < 32 for c in deposit_tx_hash):
            raise LifecycleError("field 'deposit_tx_hash' is not a valid hash")

        source_status, message = _intents.submit_deposit(
            self._http,
            deposit_address=record.deposit_address,
            tx_hash=deposit_tx_hash.strip(),
            near_sender_account=near_sender_account,
        )
        self._store.update(
            intent_id,
            owner=owner,
            updated_at=at,
            expect_state="DEPOSIT_SUBMITTED",
            deposit_tx_hash=deposit_tx_hash.strip(),
        )
        self._store.append_event(
            intent_id, owner=owner, at=at, kind="DEPOSIT_SUBMITTED",
            detail={"tx_hash": deposit_tx_hash.strip(), "source_status": source_status.value},
        )
        return {
            "ok": source_status.value == "OK",
            "intent_id": intent_id,
            "state": "DEPOSIT_SUBMITTED",
            "deposit_tx_hash": deposit_tx_hash.strip(),
            "notify_source_status": source_status.value,
            "message": message,
        }

    # -- step 4: read status and build the assurance view -------------------

    def refresh_status(
        self,
        *,
        owner: str,
        intent_id: str,
        at: str | None = None,
        expected_amount_out: str | None = None,
    ) -> dict[str, Any]:
        """Read the provider status, map the lifecycle, and update the record.

        The mapping is conservative: a provider ``SUCCESS`` becomes
        ``EXECUTION_PENDING`` or ``DESTINATION_OBSERVED``, never
        ``SETTLEMENT_VERIFIED``. Independent verification is decided in
        :meth:`assurance` by the deterministic engine over on-chain evidence.
        """
        at = at or _utc_now()
        record = self._store.get(intent_id, owner=owner)
        if record is None:
            raise LifecycleError("no such intent for this owner")
        if not record.deposit_address:
            raise LifecycleError("this intent has no deposit address yet")

        from ..adapters import oneclick

        source_report, data = oneclick.investigate(record.deposit_address, self._http)
        source_status = source_report.status
        if data is None:
            # The status could not be read (not found, or a source outage). The
            # lifecycle is unknown; this is never a failure verdict.
            lifecycle = _intents.lifecycle_view(
                None, source_available=source_status.value not in ("TIMEOUT", "NETWORK_ERROR", "RATE_LIMITED", "SERVER_ERROR")
            )
            record, changed = self._store.apply_provider_status(
                intent_id, owner=owner, provider_status="", provider_updated_at=None,
                observed_at=at, lifecycle=lifecycle.to_dict(),
            )
            self._store.append_event(
                intent_id, owner=owner, at=at, kind="STATUS_UNAVAILABLE",
                detail={"source_status": source_status.value, "message": source_report.message},
            )
            return {
                "ok": False,
                "intent_id": intent_id,
                "changed": changed,
                "source_status": source_status.value,
                "message": source_report.message,
                "lifecycle": lifecycle.to_dict(),
            }

        dest_hashes = tuple(data.destination_chain_tx_hashes)
        origin_hashes = tuple(data.origin_chain_tx_hashes)
        lifecycle = _intents.lifecycle_view(
            data.status,
            destination_tx_hashes=dest_hashes,
            origin_tx_hashes=origin_hashes,
            refunded_amount=data.refunded_amount,
            amount_out=_swap_detail(data, "amountOut"),
        )
        lifecycle_dict = lifecycle.to_dict()
        origin_check = self._origin_verification(record)
        if origin_check is not None:
            lifecycle_dict["origin_verification"] = origin_check
        destination_check = self._destination_verification(record, dest_hashes)
        if destination_check is not None:
            lifecycle_dict["destination_verification"] = destination_check
        record, changed = self._store.apply_provider_status(
            intent_id, owner=owner, provider_status=data.status,
            provider_updated_at=data.updated_at, observed_at=at, lifecycle=lifecycle_dict,
        )
        if changed:
            self._store.append_event(
                intent_id, owner=owner, at=at, kind="PROVIDER_STATUS",
                detail={"status": data.status, "label": lifecycle.label, "updated_at": data.updated_at},
            )
        return {
            "ok": True,
            "intent_id": intent_id,
            "changed": changed,
            "source_status": source_status.value,
            "provider_status": data.status,
            "lifecycle": lifecycle_dict,
            "deposit_address": record.deposit_address if record else None,
        }

    # -- independent origin-chain verification of the recorded deposit -------

    def _origin_verification(self, record: Any) -> dict[str, Any] | None:
        """Independently check the recorded deposit hash against the origin chain.

        The hash the user's wallet reported is a claim; this reads the origin
        chain and returns a structured verdict. It is read-only and only runs when
        a hash has actually been recorded. A check that cannot be completed (no
        source for the chain, or a source outage) is reported as such and never
        blocks the provider-status read that calls it.
        """
        from .origin_verify import origin_contract_address, verify_origin_deposit

        tx_hash = getattr(record, "deposit_tx_hash", None)
        if not tx_hash:
            return None
        origin_asset = getattr(record, "origin_asset", None)
        # The origin chain is the chain the user funds from. It is recorded on the
        # evaluated transaction; fall back to the asset id only if it is absent.
        chain = ""
        decision = getattr(record, "decision", None)
        evaluated = decision.get("transaction") if isinstance(decision, dict) else None
        if isinstance(evaluated, dict) and evaluated.get("chain"):
            chain = str(evaluated["chain"]).strip().lower()
        if not chain:
            chain = _chain_of(origin_asset or "")
        expected_amount = None
        quote = record.quote or {}
        q = quote.get("quote") if isinstance(quote, dict) else None
        if isinstance(q, dict):
            amount_in = q.get("amountIn")
            if isinstance(amount_in, str) and amount_in.isdigit():
                expected_amount = amount_in
        try:
            verification = verify_origin_deposit(
                chain=chain,
                tx_hash=tx_hash,
                deposit_address=record.deposit_address or "",
                token_contract=origin_contract_address(origin_asset),
                expected_amount=expected_amount,
                client=self._http,
            )
        except Exception as exc:  # noqa: BLE001 - never let a check break the status read
            return {
                "level": "UNAVAILABLE",
                "chain": chain,
                "tx_hash": tx_hash,
                "summary": f"The origin-chain check could not be completed: {exc}",
                "checks": {},
                "evidence_url": None,
                "limitations": [],
            }
        return verification.to_dict()

    # -- independent destination-chain verification of the delivery ----------

    def _destination_verification(
        self, record: Any, destination_tx_hashes: tuple[str, ...] | None = None
    ) -> dict[str, Any] | None:
        """Independently check the named destination transaction against the chain.

        The destination hash the provider reports is a claim; this reads the
        destination chain and returns a structured verdict. It is read-only and
        only runs when a destination hash is known. A check that cannot be
        completed (no source for the chain, or a source outage) is reported as such
        and never blocks the provider-status read that calls it.
        """
        from ..assets import chain_of, contract_of
        from .destination_verify import fetch_latest_block_number, verify_destination_delivery

        if destination_tx_hashes is None:
            lifecycle = record.lifecycle or {}
            destination_tx_hashes = tuple(lifecycle.get("destination_tx_hashes") or ())
        if not destination_tx_hashes:
            return None
        tx_hash = destination_tx_hashes[0]

        destination_chain = chain_of(record.destination_asset or "")
        # The expected output is the quote's promised amount; the provider's own
        # reported amount is never used as the expectation, or a shortfall would be
        # invisible.
        expected_amount = _expected_amount_out(record)
        try:
            latest_block = fetch_latest_block_number(destination_chain or "", self._http)
            verification = verify_destination_delivery(
                chain=destination_chain or "",
                tx_hash=tx_hash,
                recipient=record.recipient,
                token_contract=contract_of(record.destination_asset),
                expected_amount=expected_amount,
                client=self._http,
                latest_block_number=latest_block,
            )
        except Exception as exc:  # noqa: BLE001 - never let a check break the status read
            return {
                "level": "UNAVAILABLE",
                "chain": destination_chain,
                "tx_hash": tx_hash,
                "summary": f"The destination-chain check could not be completed: {exc}",
                "checks": {},
                "evidence_url": None,
                "limitations": [],
            }
        return verification.to_dict()

    def destination_verification(self, *, owner: str, intent_id: str) -> dict[str, Any] | None:
        """Independently verify the recorded destination hash against the chain.

        Returns ``None`` when no destination transaction hash is known. The check
        is read-only; its verdict is also recorded on the intent so a later read
        carries it forward without another network call.
        """
        record = self._store.get(intent_id, owner=owner)
        if record is None:
            return None
        verification = self._destination_verification(record)
        if verification is None:
            return None
        at = _utc_now()
        lifecycle = dict(record.lifecycle or {})
        lifecycle["destination_verification"] = verification
        self._store.update(intent_id, owner=owner, updated_at=at, lifecycle=lifecycle)
        self._store.append_event(
            intent_id, owner=owner, at=at, kind="DESTINATION_VERIFICATION",
            detail={"level": verification.get("level"), "chain": verification.get("chain")},
        )
        return verification

    # -- step 5: independent settlement assurance ---------------------------

    def assurance(
        self,
        *,
        owner: str,
        intent_id: str,
        at: str | None = None,
    ) -> dict[str, Any]:
        """Run the deterministic engine and build the independent assurance view.

        This is the only path that can yield ``VERIFIED``. It re-investigates the
        deposit address through the unchanged settlement engine, then maps the
        result onto the NEAR assurance levels, comparing the quote's expected
        output with the independently observed destination amount when both are
        known. A provider ``SUCCESS`` with no decisive evidence stays non-VERIFIED.
        """
        at = at or _utc_now()
        record = self._store.get(intent_id, owner=owner)
        if record is None:
            raise LifecycleError("no such intent for this owner")
        if not record.deposit_address:
            raise LifecycleError("this intent has no deposit address yet")

        from ..investigation import build_result, investigate

        inv = investigate(record.deposit_address, self._http)
        result = build_result(inv)

        provider_success = bool(record.provider_status == "SUCCESS")
        expected_amount_out = _expected_amount_out(record)
        observed_amount_out = _observed_amount_out(record, result)

        view: NearSettlementAssurance = settlement_assurance_from_result(
            result,
            provider_reported_success=provider_success,
            expected_amount_out=expected_amount_out,
            observed_amount_out=observed_amount_out,
            evidence=inv.evidence,
        )
        self._store.update(
            intent_id, owner=owner, updated_at=at, assurance=view.to_dict()
        )
        self._store.append_event(
            intent_id, owner=owner, at=at, kind="ASSURANCE",
            detail={"level": view.level.value, "outcome": view.outcome.value},
        )
        return {"ok": True, "intent_id": intent_id, "assurance": view.to_dict()}

    # -- reads --------------------------------------------------------------

    def get(self, *, owner: str, intent_id: str) -> dict[str, Any] | None:
        record = self._store.get(intent_id, owner=owner)
        if record is None:
            return None
        data = record.to_dict()
        quote = _intents.QuoteFields.from_dict((record.quote or {}).get("quote"))
        data["quote_expiry"] = _intents.quote_expiry(quote) if quote else None
        data["quote_approved"] = bool(record.quote_approved_at)
        data["events"] = self._store.events(intent_id, owner=owner)
        # The lifecycle label is a pure function of the stored provider status and
        # evidence. Re-derive it on read so a record written by an older label
        # mapping is presented under the current, correct semantics rather than a
        # stale one (e.g. a deposit-status label from before a semantics fix).
        if record.provider_status:
            prior = record.lifecycle or {}
            view = _intents.lifecycle_view(
                record.provider_status,
                destination_tx_hashes=tuple(prior.get("destination_tx_hashes") or ()),
                origin_tx_hashes=tuple(prior.get("origin_tx_hashes") or ()),
                refunded_amount=prior.get("refunded_amount"),
                amount_out=prior.get("amount_out"),
            )
            data["state"] = view.label
            data["lifecycle"] = view.to_dict()
            # The origin/destination checks are not re-run on read (that would hit
            # the network), so carry the last recorded verdicts forward.
            if prior.get("origin_verification"):
                data["lifecycle"]["origin_verification"] = prior["origin_verification"]
            if prior.get("destination_verification"):
                data["lifecycle"]["destination_verification"] = prior["destination_verification"]
        return data

    def list(self, *, owner: str, limit: int = 50) -> list[dict[str, Any]]:
        return [r.to_dict() for r in self._store.list_for_owner(owner, limit=limit)]

    def origin_verification(self, *, owner: str, intent_id: str) -> dict[str, Any] | None:
        """Independently verify the recorded deposit hash against the origin chain.

        Returns ``None`` when no deposit hash has been recorded. The check is
        read-only; its verdict is also recorded on the intent so a later read
        carries it forward without another network call.
        """
        record = self._store.get(intent_id, owner=owner)
        if record is None:
            return None
        verification = self._origin_verification(record)
        if verification is None:
            return None
        at = _utc_now()
        lifecycle = dict(record.lifecycle or {})
        lifecycle["origin_verification"] = verification
        self._store.update(intent_id, owner=owner, updated_at=at, lifecycle=lifecycle)
        self._store.append_event(
            intent_id, owner=owner, at=at, kind="ORIGIN_VERIFICATION",
            detail={"level": verification.get("level"), "chain": verification.get("chain")},
        )
        return verification


# -- helpers ----------------------------------------------------------------


def _authorization_id(decision: Any) -> str | None:
    auth = decision.authorization
    if auth is None:
        return None
    return getattr(auth, "authorization_id", None) or getattr(auth, "id", None)


def _chain_of(asset_id: str) -> str:
    """The chain a ``nep141:<chain>-<contract>.omft.near`` asset id names."""
    if isinstance(asset_id, str) and asset_id.startswith("nep141:"):
        rest = asset_id[len("nep141:"):]
        if "-" in rest:
            return rest.split("-", 1)[0]
    return "near"


def _swap_detail(data: Any, key: str) -> str | None:
    details = getattr(data, "swap_details", None)
    if isinstance(details, dict):
        value = details.get(key)
        if isinstance(value, str):
            return value
    return None


def _expected_amount_out(record: Any) -> str | None:
    quote = record.quote or {}
    q = quote.get("quote") if isinstance(quote, dict) else None
    if isinstance(q, dict):
        value = q.get("amount_out")
        if isinstance(value, str) and value.isdigit():
            return value
    return None


def _observed_amount_out(record: Any, result: Any) -> str | None:
    # The provider's own swapDetails.amountOut is a REPORTED value; it is used
    # only as the observed side of a comparison, and only once the destination
    # delivery is independently confirmed by the engine (the assurance builder
    # enforces that a shortfall against an unconfirmed delivery is disclosed, not
    # classified). When the engine has no confirmed delivery, this returns the
    # reported value but the builder will not classify it as PARTIAL.
    lifecycle = record.lifecycle or {}
    value = lifecycle.get("amount_out")
    if isinstance(value, str) and value.isdigit():
        return value
    return None
