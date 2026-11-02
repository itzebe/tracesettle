"""TRACESETTLE transaction security layer.

This package adds a *pre-execution* authorization boundary in front of any
transaction-signing system:

    request -> deterministic risk evaluation -> policy decision
            -> transaction-bound authorization -> independent signer validation
            -> execution or refusal -> audit record

Honest scope. This layer does **not** sign real transactions and cannot block an
arbitrary blockchain transaction. It prevents an unauthorized transaction from
reaching a *signer that consults it*. The reference signer in
:mod:`tracesettle.guard.signer` is the enforcement point, and it fails closed.

Standard library only, like the rest of the project.
"""

from __future__ import annotations

from .audit import AuditLog, AuditRecord
from .authorization import (
    Authorization,
    AuthorizationAuthority,
    AuthorizationStore,
    AuthVerification,
    InMemoryReplayStore,
)
from .model import (
    AuthState,
    ControlOutcome,
    ControlResult,
    Decision,
    EvaluationContext,
    FindingSeverity,
    GuardDecision,
    Incident,
    IncidentSeverity,
    IncidentStatus,
    RequestFingerprint,
    RiskFinding,
    SignOutcome,
    SignResult,
    TransactionRequest,
)
from .monitor import SecurityMonitor
from .policy import DEFAULT_POLICY, PolicyConfig, load_policy
from .rules import evaluate_controls
from .service import GuardService, RequestValidationError, request_from_payload
from .signer import ExecutionReceipt, ReferenceSigner, SignRequest, SimulatedExecutor
from .state import (
    DurableReplayStore,
    DurableRevocationStore,
    GuardStateStore,
    StateStoreError,
    open_state_store,
)

__all__ = [
    "AuditLog",
    "AuditRecord",
    "AuthState",
    "AuthVerification",
    "Authorization",
    "AuthorizationAuthority",
    "AuthorizationStore",
    "ControlOutcome",
    "ControlResult",
    "DEFAULT_POLICY",
    "Decision",
    "DurableReplayStore",
    "DurableRevocationStore",
    "EvaluationContext",
    "ExecutionReceipt",
    "FindingSeverity",
    "GuardDecision",
    "GuardService",
    "GuardStateStore",
    "InMemoryReplayStore",
    "Incident",
    "IncidentSeverity",
    "IncidentStatus",
    "PolicyConfig",
    "ReferenceSigner",
    "RequestFingerprint",
    "RequestValidationError",
    "RiskFinding",
    "SecurityMonitor",
    "SignOutcome",
    "SignRequest",
    "SignResult",
    "SimulatedExecutor",
    "StateStoreError",
    "TransactionRequest",
    "evaluate_controls",
    "load_policy",
    "open_state_store",
    "request_from_payload",
]
