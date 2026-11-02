"""NEAR access-key permission analysis.

Source of truth is ``docs.near.org/protocol/accounts-contracts/access-keys`` and
``.../gas-keys``. The facts this module encodes, because they are the ones
people get wrong:

* **Function-Call keys** can only sign transactions that call a *single*
  ``receiver_id``. They **cannot transfer NEAR** and **cannot attach NEAR
  tokens** to a call. ``method_names`` may restrict which methods are callable;
  omitted means every method on that contract. ``allowance`` caps the NEAR spent
  on gas; omitted means the key can consume unlimited gas until it runs out.
* **Full-Access keys** can do anything on the account: transfer NEAR, add or
  remove keys, deploy contracts, delete the account. They must never be shared.
* **Gas keys** (NEP-611) hold their own prepaid balance and have up to 1,024
  nonce lanes. A function-call gas key cannot set an ``allowance``.
* A function-call key is a real boundary, but a **narrow** one: it stops NEAR
  transfers and calls to other contracts, and it does **not** stop every method
  on its one contract when ``method_names`` is omitted. An empty
  ``method_names`` is therefore reported as "all methods", not "safe".

This module analyses a declared key. It never requests, derives, or stores a
private key, and never adds or deletes a key on a real account.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any

#: The one action a Function-Call key can perform on its contract.
FUNCTION_CALL = "FunctionCall"
FULL_ACCESS = "FullAccess"

#: NEAR amounts are in yoctoNEAR (1 NEAR = 10**24 yoctoNEAR).
YOCTO_PER_NEAR = Decimal(10) ** 24


class AccessKeyPermission(str, enum.Enum):
    """The permission class of a NEAR access key."""

    FUNCTION_CALL = "FUNCTION_CALL"
    FULL_ACCESS = "FULL_ACCESS"
    #: A permission shape we do not recognise. Treated as unrestricted.
    UNKNOWN = "UNKNOWN"

    @property
    def unrestricted(self) -> bool:
        return self is not AccessKeyPermission.FUNCTION_CALL


class AccessKeyRisk(str, enum.Enum):
    """How dangerous the key's declared scope is for an agent."""

    #: Full access, or an unrecognised permission: treat as account-wide control.
    CRITICAL = "CRITICAL"
    #: Function-call key with no method restriction on its contract.
    HIGH = "HIGH"
    #: Function-call key restricted to specific methods.
    MEDIUM = "MEDIUM"
    #: Function-call key restricted to specific methods and with a bounded allowance.
    LOW = "LOW"


_RISK_RANK = {
    AccessKeyRisk.LOW: 0,
    AccessKeyRisk.MEDIUM: 1,
    AccessKeyRisk.HIGH: 2,
    AccessKeyRisk.CRITICAL: 3,
}


@dataclass(frozen=True)
class AccessKeyAnalysis:
    """A deterministic analysis of one declared access key.

    Every field is derived from the declared permission only. No private key is
    involved and none is requested.
    """

    permission: AccessKeyPermission
    receiver_id: str | None = None
    method_names: tuple[str, ...] = ()
    allowance_yocto: Decimal | None = None
    is_gas_key: bool = False
    num_nonces: int | None = None
    risk: AccessKeyRisk = AccessKeyRisk.CRITICAL
    #: What this key provably can and cannot do. Each entry is a plain fact.
    capabilities: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    @property
    def restricted(self) -> bool:
        return self.permission is AccessKeyPermission.FUNCTION_CALL

    @property
    def can_transfer_near(self) -> bool:
        """Only a full-access key can transfer NEAR.

        A function-call key cannot transfer NEAR and cannot attach NEAR tokens
        to a contract call. That is the property agents most often assume away.
        """
        return self.permission is AccessKeyPermission.FULL_ACCESS

    @property
    def can_add_keys(self) -> bool:
        return self.permission is AccessKeyPermission.FULL_ACCESS

    @property
    def methods_unrestricted(self) -> bool:
        return self.restricted and not self.method_names

    def allows_call(self, *, receiver_id: str, method_name: str | None = None) -> bool:
        """Whether this key may call ``method_name`` on ``receiver_id``."""
        if self.permission is AccessKeyPermission.FULL_ACCESS:
            return True
        if self.permission is AccessKeyPermission.UNKNOWN:
            return True
        if not self.receiver_id or self.receiver_id != receiver_id:
            return False
        if not self.method_names:
            return True
        if method_name is None:
            return False
        return method_name in self.method_names

    def to_dict(self) -> dict[str, Any]:
        return {
            "permission": self.permission.value,
            "receiver_id": self.receiver_id,
            "method_names": list(self.method_names),
            "allowance_yocto": (
                None if self.allowance_yocto is None else str(self.allowance_yocto)
            ),
            "allowance_near": (
                None
                if self.allowance_yocto is None
                else str(self.allowance_yocto / YOCTO_PER_NEAR)
            ),
            "is_gas_key": self.is_gas_key,
            "num_nonces": self.num_nonces,
            "risk": self.risk.value,
            "restricted": self.restricted,
            "can_transfer_near": self.can_transfer_near,
            "can_add_keys": self.can_add_keys,
            "methods_unrestricted": self.methods_unrestricted,
            "capabilities": list(self.capabilities),
            "limitations": list(self.limitations),
            "warnings": list(self.warnings),
        }


def _dec(value: Any, field_name: str) -> Decimal | None:
    if value is None:
        return None
    if isinstance(value, bool) or isinstance(value, float):
        raise ValueError(f"{field_name} must be a decimal string or integer")
    try:
        parsed = Decimal(str(value).strip())
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"{field_name} is not a valid number") from exc
    if not parsed.is_finite() or parsed < 0:
        raise ValueError(f"{field_name} must be a finite non-negative number")
    return parsed


def parse_access_key(raw: Any) -> AccessKeyAnalysis:
    """Analyse a declared NEAR access key from its JSON shape.

    Accepts the NEAR RPC ``access_key`` view shape (``{"permission": ...}``) and
    a flat form used by the demo fixtures. An unrecognised permission is treated
    as unrestricted, never as safe.
    """
    if not isinstance(raw, dict):
        raise ValueError("access key must be a JSON object")

    # Unwrap the RPC view envelope when present.
    body = raw.get("access_key") if isinstance(raw.get("access_key"), dict) else raw
    permission_raw = body.get("permission")

    is_gas_key = bool(body.get("is_gas_key", raw.get("is_gas_key", False)))
    num_nonces = body.get("num_nonces", raw.get("num_nonces"))
    if num_nonces is not None and (
        isinstance(num_nonces, bool) or not isinstance(num_nonces, int) or num_nonces < 1
    ):
        raise ValueError("num_nonces must be a positive integer")

    if isinstance(permission_raw, str):
        # RPC view shape: "FullAccess" or {"FunctionCall": {...}} handled below.
        kind = permission_raw.strip()
        function_call = None
    elif isinstance(permission_raw, dict):
        if FUNCTION_CALL in permission_raw:
            kind = FUNCTION_CALL
            function_call = permission_raw.get(FUNCTION_CALL)
        elif FULL_ACCESS in permission_raw:
            kind = FULL_ACCESS
            function_call = None
        else:
            kind = "UNKNOWN"
            function_call = None
    elif permission_raw is None:
        # Flat fixture form.
        kind = str(body.get("permission_kind", "UNKNOWN")).strip()
        function_call = body.get("function_call")
    else:
        kind = "UNKNOWN"
        function_call = None

    if kind == FUNCTION_CALL:
        if not isinstance(function_call, dict):
            # A function-call key with no details is still restricted to nothing
            # we can name; treat the receiver as unknown, which denies calls.
            function_call = {}
        receiver_id = str(function_call.get("receiver_id", "")).strip() or None
        method_names = tuple(
            str(m) for m in (function_call.get("method_names") or []) if str(m).strip()
        )
        allowance = _dec(function_call.get("allowance"), "function_call.allowance")
        return _build_function_call(
            receiver_id=receiver_id,
            method_names=method_names,
            allowance=allowance,
            is_gas_key=is_gas_key,
            num_nonces=num_nonces,
        )

    if kind == FULL_ACCESS:
        return _build_full_access(is_gas_key=is_gas_key, num_nonces=num_nonces)

    return AccessKeyAnalysis(
        permission=AccessKeyPermission.UNKNOWN,
        is_gas_key=is_gas_key,
        num_nonces=num_nonces,
        risk=AccessKeyRisk.CRITICAL,
        capabilities=("the permission shape is not recognised",),
        limitations=(),
        warnings=(
            "Unrecognised access-key permission: treated as unrestricted. Do not sign with it.",
        ),
    )


def _build_full_access(*, is_gas_key: bool, num_nonces: int | None) -> AccessKeyAnalysis:
    return AccessKeyAnalysis(
        permission=AccessKeyPermission.FULL_ACCESS,
        is_gas_key=is_gas_key,
        num_nonces=num_nonces,
        risk=AccessKeyRisk.CRITICAL,
        capabilities=(
            "transfer NEAR",
            "create and delete sub-accounts",
            "add and remove access keys",
            "deploy a contract",
            "call any method on any contract",
        ),
        limitations=(),
        warnings=(
            "A full-access key is total control of the account. It must never be shared with "
            "an agent or a third-party service.",
        ),
    )


def _build_function_call(
    *,
    receiver_id: str | None,
    method_names: tuple[str, ...],
    allowance: Decimal | None,
    is_gas_key: bool,
    num_nonces: int | None,
) -> AccessKeyAnalysis:
    capabilities = [
        f"call methods on the contract {receiver_id!r}" if receiver_id else "call a contract",
    ]
    limitations = [
        "cannot transfer NEAR",
        "cannot attach NEAR tokens to a contract call",
        "cannot add or remove access keys",
        "cannot deploy a contract",
        "cannot delete the account",
        "cannot call any contract other than its single receiver_id",
    ]
    warnings: list[str] = []

    if not receiver_id:
        warnings.append(
            "The function-call key names no receiver_id, so no call can be matched to it; "
            "treat it as unusable rather than unrestricted."
        )

    if method_names:
        capabilities.append(f"is limited to the methods {sorted(method_names)}")
        risk = AccessKeyRisk.MEDIUM
    else:
        capabilities.append("may call every method on its receiver contract (no method_names)")
        warnings.append(
            "No method_names were declared, so this key can call every method on its contract. "
            "A function-call key is not a per-method sandbox unless method_names is set."
        )
        risk = AccessKeyRisk.HIGH

    if allowance is not None:
        capabilities.append(
            f"has a gas allowance of {allowance / YOCTO_PER_NEAR} NEAR, after which it stops working"
        )
        limitations.append(
            "once the allowance is exhausted the key can no longer sign; there is no automatic top-up"
        )
        if risk is AccessKeyRisk.MEDIUM:
            risk = AccessKeyRisk.LOW
    else:
        warnings.append(
            "No allowance was declared, so the key can consume unlimited gas until the account's "
            "own balance runs out. Set an allowance for an agent key."
        )

    if is_gas_key:
        capabilities.append(
            "holds its own prepaid gas balance and up to 1,024 nonce lanes (NEP-611 gas key)"
        )
        limitations.append(
            "a function-call gas key cannot set an allowance; its prepaid balance is the budget"
        )

    return AccessKeyAnalysis(
        permission=AccessKeyPermission.FUNCTION_CALL,
        receiver_id=receiver_id,
        method_names=method_names,
        allowance_yocto=allowance,
        is_gas_key=is_gas_key,
        num_nonces=num_nonces,
        risk=risk,
        capabilities=tuple(capabilities),
        limitations=tuple(limitations),
        warnings=tuple(warnings),
    )


def analyze_access_keys(keys: list[Any]) -> tuple[AccessKeyAnalysis, ...]:
    """Analyse every declared key, keeping input order for a stable report."""
    return tuple(parse_access_key(key) for key in keys)


def worst_risk(analyses: tuple[AccessKeyAnalysis, ...]) -> AccessKeyRisk:
    """The most dangerous declared permission, compared by rank not by name."""
    if not analyses:
        return AccessKeyRisk.CRITICAL
    return max((a.risk for a in analyses), key=lambda r: _RISK_RANK[r])


def key_supports_operation(
    analysis: AccessKeyAnalysis,
    *,
    operation: str,
    receiver_id: str | None = None,
    method_name: str | None = None,
    transfers_near: bool = False,
) -> tuple[bool, str]:
    """Whether a key's declared scope covers an operation.

    Returns ``(allowed, reason)``. ``transfers_near`` is true when the operation
    would move NEAR (a transfer, or a call that attaches NEAR), which a
    function-call key can never do.
    """
    if analysis.permission is AccessKeyPermission.FULL_ACCESS:
        return True, "full-access key covers every operation"
    if analysis.permission is AccessKeyPermission.UNKNOWN:
        return True, "unrecognised permission treated as unrestricted (do not rely on it)"
    if transfers_near:
        return False, (
            "a function-call key cannot transfer NEAR or attach NEAR tokens to a call"
        )
    if operation.upper() == "FUNCTION_CALL":
        if analysis.allows_call(receiver_id=receiver_id or "", method_name=method_name):
            return True, "function-call key covers this receiver and method"
        return False, (
            "the function-call key is not scoped to this receiver_id or method_name"
        )
    return False, (
        f"a function-call key cannot perform the operation {operation!r}; only a "
        "full-access key can"
    )
