"""Deterministic, explainable risk controls.

Each control is a pure function of (request, policy, context). It returns a
:class:`ControlResult` with a stable ``code``, a human-readable ``detail``, and
any :class:`RiskFinding` it observed. No control consults a model, a score, or
the network, so a decision can always be reproduced from the recorded inputs.

The decision is the maximum of the control outcomes; see
:func:`tracesettle.guard.service.evaluate_request`. A control can therefore only
make the outcome stricter, never weaker.
"""

from __future__ import annotations

from decimal import Decimal

from .model import (
    ASSERTED_APPROVAL_FIELDS,
    ControlOutcome,
    ControlResult,
    EvaluationContext,
    FindingSeverity,
    RiskFinding,
    TransactionRequest,
)
from .policy import PolicyConfig, normalize_destination

# --- control codes ---------------------------------------------------------

CONTROL_IDENTITY = "IDENTITY_ALLOWLIST"
CONTROL_DESTINATION = "DESTINATION_POLICY"
CONTROL_AMOUNT = "AMOUNT_LIMITS"
CONTROL_VELOCITY = "VELOCITY"
CONTROL_REJECTED_AUTH = "REJECTED_AUTHORIZATION_ATTEMPTS"
CONTROL_CLIENT_ASSERTIONS = "CLIENT_ASSERTED_APPROVAL"
CONTROL_INTEGRITY = "REQUEST_INTEGRITY"


def _finding(
    code: str,
    severity: FindingSeverity,
    title: str,
    detail: str,
    policy: str,
    observed: dict[str, str] | None = None,
) -> RiskFinding:
    return RiskFinding(
        code=code,
        severity=severity,
        title=title,
        detail=detail,
        policy=policy,
        observed=observed or {},
    )


def _ok(code: str, title: str, policy: str, detail: str) -> ControlResult:
    return ControlResult(
        code=code, title=title, outcome=ControlOutcome.PASS, detail=detail, policy=policy
    )


# --- controls --------------------------------------------------------------


def control_identity(request: TransactionRequest, policy: PolicyConfig, _ctx: EvaluationContext) -> ControlResult:
    """Is the requesting service identity known, enabled, and allowed this operation?"""
    title = "Requesting service identity"
    service = policy.service(request.service_id)
    if service is None:
        return ControlResult(
            code=CONTROL_IDENTITY,
            title=title,
            outcome=ControlOutcome.BLOCK,
            detail=f"Service identity '{request.service_id}' is not a registered transaction requester.",
            policy="identity allowlist",
            findings=(
                _finding(
                    "UNAUTHORIZED_SERVICE_IDENTITY",
                    FindingSeverity.CRITICAL,
                    "Unregistered service identity",
                    f"'{request.service_id}' is not present in the service allowlist, so no "
                    "transaction it requests may be authorized.",
                    "identity allowlist",
                    {"service_id": request.service_id},
                ),
            ),
        )
    if not service.enabled:
        return ControlResult(
            code=CONTROL_IDENTITY,
            title=title,
            outcome=ControlOutcome.BLOCK,
            detail=f"Service identity '{request.service_id}' is disabled.",
            policy="identity allowlist",
            findings=(
                _finding(
                    "SERVICE_IDENTITY_DISABLED",
                    FindingSeverity.HIGH,
                    "Service identity disabled",
                    f"'{request.service_id}' exists but is disabled, so it may not request transfers.",
                    "identity allowlist",
                    {"service_id": request.service_id},
                ),
            ),
        )
    operation = request.operation.strip().upper()
    if service.allowed_operations and operation not in service.allowed_operations:
        return ControlResult(
            code=CONTROL_IDENTITY,
            title=title,
            outcome=ControlOutcome.BLOCK,
            detail=f"Operation '{operation}' is not permitted for '{request.service_id}'.",
            policy="operation allowlist",
            findings=(
                _finding(
                    "UNAUTHORIZED_OPERATION",
                    FindingSeverity.HIGH,
                    "Operation not permitted",
                    f"'{request.service_id}' may only request "
                    f"{sorted(service.allowed_operations)}; '{operation}' was requested.",
                    "operation allowlist",
                    {"operation": operation},
                ),
            ),
        )
    if service.allowed_chains and request.chain.strip().lower() not in service.allowed_chains:
        return ControlResult(
            code=CONTROL_IDENTITY,
            title=title,
            outcome=ControlOutcome.BLOCK,
            detail=f"Chain '{request.chain}' is not permitted for '{request.service_id}'.",
            policy="chain allowlist",
            findings=(
                _finding(
                    "UNAUTHORIZED_CHAIN",
                    FindingSeverity.HIGH,
                    "Chain not permitted",
                    f"'{request.service_id}' may only transact on {sorted(service.allowed_chains)}.",
                    "chain allowlist",
                    {"chain": request.chain},
                ),
            ),
        )
    if service.allowed_assets and request.asset.strip().upper() not in service.allowed_assets:
        return ControlResult(
            code=CONTROL_IDENTITY,
            title=title,
            outcome=ControlOutcome.BLOCK,
            detail=f"Asset '{request.asset}' is not permitted for '{request.service_id}'.",
            policy="asset allowlist",
            findings=(
                _finding(
                    "UNAUTHORIZED_ASSET",
                    FindingSeverity.HIGH,
                    "Asset not permitted",
                    f"'{request.service_id}' may only transfer {sorted(service.allowed_assets)}.",
                    "asset allowlist",
                    {"asset": request.asset},
                ),
            ),
        )
    return _ok(
        CONTROL_IDENTITY,
        title,
        "identity allowlist",
        f"'{request.service_id}' is registered and may request {operation} on {request.chain}.",
    )


def control_destination(request: TransactionRequest, policy: PolicyConfig, _ctx: EvaluationContext) -> ControlResult:
    """Is the destination explicitly blocked, explicitly approved, or unlisted?"""
    title = "Destination policy"
    destination = normalize_destination(request.destination)
    if not destination:
        return ControlResult(
            code=CONTROL_DESTINATION,
            title=title,
            outcome=ControlOutcome.BLOCK,
            detail="No destination was supplied.",
            policy="destination policy",
            findings=(
                _finding(
                    "MISSING_DESTINATION",
                    FindingSeverity.HIGH,
                    "Missing destination",
                    "A transfer with no destination cannot be authorized.",
                    "destination policy",
                ),
            ),
        )
    if destination in policy.blocked_destinations:
        return ControlResult(
            code=CONTROL_DESTINATION,
            title=title,
            outcome=ControlOutcome.BLOCK,
            detail=f"Destination {destination} is on the denied list.",
            policy="destination denylist",
            findings=(
                _finding(
                    "DESTINATION_DENIED",
                    FindingSeverity.CRITICAL,
                    "Destination on denylist",
                    f"{destination} is explicitly denied by policy.",
                    "destination denylist",
                    {"destination": destination},
                ),
            ),
        )
    if destination in policy.approved_destinations:
        return _ok(
            CONTROL_DESTINATION,
            title,
            "destination allowlist",
            f"Destination {destination} is on the approved list.",
        )
    severity = FindingSeverity.HIGH
    outcome = ControlOutcome.BLOCK if not policy.allow_unlisted_destinations else ControlOutcome.REVIEW
    finding = _finding(
        "UNAPPROVED_DESTINATION",
        severity,
        "Destination not approved",
        f"{destination} is not on the approved destination list. "
        + (
            "Unlisted destinations are refused by this policy."
            if outcome is ControlOutcome.BLOCK
            else "Unlisted destinations require an explicit human approval."
        ),
        "destination allowlist",
        {"destination": destination},
    )
    return ControlResult(
        code=CONTROL_DESTINATION,
        title=title,
        outcome=outcome,
        detail=finding.detail,
        policy="destination allowlist",
        findings=(finding,),
    )


def control_amount(request: TransactionRequest, policy: PolicyConfig, _ctx: EvaluationContext) -> ControlResult:
    """Is the amount within the per-transaction limit, and does it need approval?"""
    title = "Amount limits"
    service = policy.service(request.service_id)
    limit = None
    if service is not None and service.max_amount_per_transaction is not None:
        limit = service.max_amount_per_transaction
    if limit is None:
        limit = policy.per_transaction_limit
    amount: Decimal = request.amount

    if limit is not None and amount > limit:
        return ControlResult(
            code=CONTROL_AMOUNT,
            title=title,
            outcome=ControlOutcome.BLOCK,
            detail=f"Amount {request.amount_raw} exceeds the per-transaction limit {limit}.",
            policy="per-transaction limit",
            findings=(
                _finding(
                    "AMOUNT_EXCEEDS_LIMIT",
                    FindingSeverity.HIGH,
                    "Amount exceeds per-transaction limit",
                    f"Requested {request.amount_raw} {request.asset}; the limit is {limit}.",
                    "per-transaction limit",
                    {"amount": request.amount_raw, "limit": str(limit)},
                ),
            ),
        )

    threshold = None
    if service is not None and service.approval_threshold is not None:
        threshold = service.approval_threshold
    if threshold is None:
        threshold = policy.approval_threshold
    if threshold is not None and amount > threshold:
        finding = _finding(
            "AMOUNT_REQUIRES_APPROVAL",
            FindingSeverity.MEDIUM,
            "Amount above approval threshold",
            f"Requested {request.amount_raw} {request.asset}; amounts above {threshold} "
            f"need {policy.min_approvals} human approval(s).",
            "approval threshold",
            {"amount": request.amount_raw, "threshold": str(threshold)},
        )
        return ControlResult(
            code=CONTROL_AMOUNT,
            title=title,
            outcome=ControlOutcome.REVIEW,
            detail=finding.detail,
            policy="approval threshold",
            findings=(finding,),
        )
    return _ok(
        CONTROL_AMOUNT,
        title,
        "per-transaction limit",
        f"Amount {request.amount_raw} {request.asset} is within the limit"
        + (f" of {limit}." if limit is not None else "."),
    )


def control_velocity(request: TransactionRequest, policy: PolicyConfig, ctx: EvaluationContext) -> ControlResult:
    """Has this service been transacting or being blocked faster than policy allows?"""
    title = "Transaction velocity"
    window = policy.window_seconds
    if ctx.recent_blocked_count >= policy.max_blocked_per_window:
        finding = _finding(
            "ABNORMAL_BLOCK_RATE",
            FindingSeverity.HIGH,
            "Abnormal blocked-request rate",
            f"{ctx.recent_blocked_count} requests from '{request.service_id}' were blocked in the "
            f"last {window}s (limit {policy.max_blocked_per_window}).",
            "velocity limits",
            {"blocked_in_window": str(ctx.recent_blocked_count)},
        )
        return ControlResult(
            code=CONTROL_VELOCITY,
            title=title,
            outcome=ControlOutcome.HOLD,
            detail=finding.detail,
            policy="velocity limits",
            findings=(finding,),
        )
    if ctx.recent_request_count >= policy.max_requests_per_window:
        finding = _finding(
            "REQUEST_VELOCITY_EXCEEDED",
            FindingSeverity.HIGH,
            "Request velocity exceeded",
            f"{ctx.recent_request_count} requests from '{request.service_id}' in the last "
            f"{window}s (limit {policy.max_requests_per_window}).",
            "velocity limits",
            {"requests_in_window": str(ctx.recent_request_count)},
        )
        return ControlResult(
            code=CONTROL_VELOCITY,
            title=title,
            outcome=ControlOutcome.HOLD,
            detail=finding.detail,
            policy="velocity limits",
            findings=(finding,),
        )

    service = policy.service(request.service_id)
    window_limit = service.max_amount_per_window if service else None
    if window_limit is not None:
        key = f"{request.service_id}:{request.asset.strip().upper()}"
        used = ctx.window_volume.get(key, Decimal(0))
        if used + request.amount > window_limit:
            finding = _finding(
                "WINDOW_VOLUME_EXCEEDED",
                FindingSeverity.HIGH,
                "Rolling window volume exceeded",
                f"{used + request.amount} {request.asset} would be authorized for "
                f"'{request.service_id}' in the last {window}s (limit {window_limit}).",
                "velocity limits",
                {"projected_volume": str(used + request.amount), "limit": str(window_limit)},
            )
            return ControlResult(
                code=CONTROL_VELOCITY,
                title=title,
                outcome=ControlOutcome.HOLD,
                detail=finding.detail,
                policy="velocity limits",
                findings=(finding,),
            )
    return _ok(
        CONTROL_VELOCITY,
        title,
        "velocity limits",
        f"{ctx.recent_request_count} requests in the last {window}s, within the limit "
        f"of {policy.max_requests_per_window}.",
    )


def control_rejected_authorizations(
    request: TransactionRequest, policy: PolicyConfig, ctx: EvaluationContext
) -> ControlResult:
    """Have authorization attempts for this service been repeatedly rejected?

    Repeated rejections at the signing boundary are the signature of a caller
    trying to make a transaction it cannot legitimately authorize, so the guard
    stops issuing authorizations until an operator looks.
    """
    title = "Rejected authorization attempts"
    if ctx.recent_rejected_authorizations >= policy.max_rejected_authorizations:
        finding = _finding(
            "REPEATED_AUTHORIZATION_REJECTIONS",
            FindingSeverity.HIGH,
            "Repeated rejected authorization attempts",
            f"{ctx.recent_rejected_authorizations} authorization attempts for "
            f"'{request.service_id}' were rejected in the last {policy.window_seconds}s "
            f"(limit {policy.max_rejected_authorizations}).",
            "rejected authorization attempts",
            {"rejected_in_window": str(ctx.recent_rejected_authorizations)},
        )
        return ControlResult(
            code=CONTROL_REJECTED_AUTH,
            title=title,
            outcome=ControlOutcome.HOLD,
            detail=finding.detail,
            policy="rejected authorization attempts",
            findings=(finding,),
        )
    return _ok(
        CONTROL_REJECTED_AUTH,
        title,
        "rejected authorization attempts",
        f"{ctx.recent_rejected_authorizations} rejected authorization attempt(s) in the window, "
        f"below the limit of {policy.max_rejected_authorizations}.",
    )


def control_client_assertions(
    request: TransactionRequest, _policy: PolicyConfig, _ctx: EvaluationContext
) -> ControlResult:
    """Ignore, and report, any client-supplied approval or bypass flag.

    A caller that asserts its own approval is trying to move the authorization
    decision out of the guard. The flag is never honoured; its presence is
    itself a finding that requires human review.
    """
    title = "Client-asserted approval"
    asserted = tuple(
        sorted(
            {
                str(name)
                for name in request.asserted_approval_fields
                if str(name).strip().lower() in ASSERTED_APPROVAL_FIELDS
            }
        )
    )
    if asserted:
        finding = _finding(
            "CLIENT_ASSERTED_APPROVAL_IGNORED",
            FindingSeverity.HIGH,
            "Client-asserted approval ignored",
            "The request carried fields that attempt to assert approval or bypass checks "
            f"({', '.join(asserted)}). These are never honoured; the request needs human review.",
            "no client-trusted approval",
            {"fields": ", ".join(asserted)},
        )
        return ControlResult(
            code=CONTROL_CLIENT_ASSERTIONS,
            title=title,
            outcome=ControlOutcome.REVIEW,
            detail=finding.detail,
            policy="no client-trusted approval",
            findings=(finding,),
        )
    return _ok(
        CONTROL_CLIENT_ASSERTIONS,
        title,
        "no client-trusted approval",
        "No client-supplied approval or bypass fields were present.",
    )


def control_request_integrity(
    request: TransactionRequest, _policy: PolicyConfig, _ctx: EvaluationContext
) -> ControlResult:
    """Are the declared parameters internally consistent and well formed?"""
    title = "Request integrity"
    problems: list[RiskFinding] = []
    if not request.request_id.strip():
        problems.append(
            _finding(
                "MISSING_REQUEST_ID",
                FindingSeverity.MEDIUM,
                "Missing request reference",
                "The request carries no request_id, so it cannot be audited or correlated.",
                "request integrity",
            )
        )
    if not request.service_id.strip():
        problems.append(
            _finding(
                "MISSING_SERVICE_ID",
                FindingSeverity.HIGH,
                "Missing service identity",
                "A transfer with no requesting identity cannot be authorized.",
                "request integrity",
            )
        )
    if not request.chain.strip():
        problems.append(
            _finding(
                "MISSING_CHAIN",
                FindingSeverity.HIGH,
                "Missing chain",
                "A transfer with no chain cannot be authorized.",
                "request integrity",
            )
        )
    if not request.asset.strip():
        problems.append(
            _finding(
                "MISSING_ASSET",
                FindingSeverity.HIGH,
                "Missing asset",
                "A transfer with no asset cannot be authorized.",
                "request integrity",
            )
        )
    if request.amount == 0:
        problems.append(
            _finding(
                "ZERO_AMOUNT",
                FindingSeverity.MEDIUM,
                "Zero amount",
                "A zero-amount transfer is not a meaningful settlement request.",
                "request integrity",
            )
        )
    if problems:
        # Compare by rank, never by the string value: "MEDIUM" sorts after
        # "HIGH" alphabetically, which would silently downgrade the outcome.
        worst = max(problems, key=lambda p: p.severity.rank).severity
        outcome = ControlOutcome.BLOCK if worst.rank >= FindingSeverity.HIGH.rank else ControlOutcome.HOLD
        return ControlResult(
            code=CONTROL_INTEGRITY,
            title=title,
            outcome=outcome,
            detail="; ".join(p.detail for p in problems),
            policy="request integrity",
            findings=tuple(problems),
        )
    return _ok(CONTROL_INTEGRITY, title, "request integrity", "All required parameters are present.")


#: Evaluation order is fixed so the reported control list is stable.
CONTROLS = (
    control_identity,
    control_destination,
    control_amount,
    control_velocity,
    control_rejected_authorizations,
    control_client_assertions,
    control_request_integrity,
)


def evaluate_controls(
    request: TransactionRequest, policy: PolicyConfig, ctx: EvaluationContext
) -> tuple[ControlResult, ...]:
    """Run every control, in a fixed order, with no short-circuiting.

    Every control runs even after one has blocked, so the operator sees the full
    picture rather than only the first failure.
    """
    return tuple(control(request, policy, ctx) for control in CONTROLS)
