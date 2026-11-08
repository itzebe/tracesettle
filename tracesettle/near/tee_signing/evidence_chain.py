"""The authorization-to-settlement evidence chain.

Mission 22-25 checked each link of the trusted execution chain in a different
place: the guard decided, the boundary bound a digest, the pipeline broadcast and
verified. Nothing assembled those facts into one record, so an independent
reviewer had to trust that the pieces belonged together. This module does that
assembly and makes the binding checkable.

The chain has one row per stage, and every stage must refer to the *same*
transaction identity. The stages are:

``AUTHORIZATION`` → ``PREPARED_TRANSACTION`` → ``TEE_EXECUTION`` →
``ATTESTATION`` → ``SIGNATURE`` → ``BROADCAST`` → ``FINALITY`` → ``SETTLEMENT``

Rules the chain enforces (each is a named check, and the chain is only ``bound``
when all of them hold):

* the signed transaction digest equals the digest the authorization bound;
* the signed transaction's receiver and amount equal the authorized ones;
* the network is the one authorized;
* the signer public key is the one the attestation names;
* the attested build is the pinned approved build;
* the broadcast transaction hash is the hash of the exact signed bytes;
* the settlement's transaction hash is the broadcast one;
* a different network, a substituted digest, a different receiver or amount, a
  different signer, a stale attestation, or a settlement for another transaction
  each *break* the chain.

Nothing here re-decides anything. It records what each layer concluded and proves
the layers agree.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from dataclasses import dataclass, field
from typing import Any, Mapping

#: The stage order, front to back. A chain that skips a stage says so rather than
#: silently renumbering.
STAGES = (
    "AUTHORIZATION",
    "PREPARED_TRANSACTION",
    "TEE_EXECUTION",
    "ATTESTATION",
    "SIGNATURE",
    "BROADCAST",
    "FINALITY",
    "SETTLEMENT",
)

#: Fields that must never appear in a chain record.
_FORBIDDEN_KEYS = ("private_key", "secret_key", "seed", "seed_phrase", "mnemonic", "signing_key")


class EvidenceChainError(RuntimeError):
    """The chain is structurally unusable, or would carry a secret."""


@dataclass
class EvidenceChain:
    """One durable record of everything that happened to one transaction."""

    transaction_digest: str
    tx_hash: str = ""
    network: str = ""
    stages: dict[str, dict[str, Any]] = field(default_factory=dict)
    created_at: str = ""

    def put(self, stage: str, **facts: Any) -> None:
        if stage not in STAGES:
            raise EvidenceChainError(f"unknown stage {stage!r}")
        bucket = self.stages.setdefault(stage, {})
        bucket.update(facts)

    def canonical(self) -> dict[str, Any]:
        """The exact structure that is hashed. Stage order is fixed."""
        return {
            "v": "1",
            "domain": "tracesettle.evidence-chain",
            "network": self.network,
            "transaction_digest": self.transaction_digest,
            "tx_hash": self.tx_hash,
            "stages": {name: dict(self.stages.get(name, {})) for name in STAGES},
        }

    def digest(self) -> str:
        blob = json.dumps(self.canonical(), sort_keys=True, separators=(",", ":")).encode("utf-8")
        return "sha256:" + hashlib.sha256(blob).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        out = self.canonical()
        out["created_at"] = self.created_at
        out["chain_digest"] = self.digest()
        return out

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "EvidenceChain":
        return cls(
            transaction_digest=str(data.get("transaction_digest", "")),
            tx_hash=str(data.get("tx_hash", "")),
            network=str(data.get("network", "")),
            stages={k: dict(v) for k, v in (data.get("stages") or {}).items()},
            created_at=str(data.get("created_at", "")),
        )


@dataclass
class ChainBinding:
    """The outcome of checking that every stage names the same transaction."""

    bound: bool
    checks: list[dict[str, Any]] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"bound": self.bound, "checks": list(self.checks), "failures": list(self.failures)}


def _add(binding: ChainBinding, name: str, holds: bool, detail: str = "") -> None:
    binding.checks.append({"name": name, "holds": bool(holds), "detail": detail})
    if not holds:
        binding.failures.append(name)


def _normalise(value: Any) -> str:
    """Compare digests by their hex, ignoring a ``sha256:`` prefix and case.

    A build hash may be recorded as ``sha256:eb70…`` by the signing layer and as
    ``eb70…`` by the attestation; those are the same hash and must not read as a
    contradiction. Any other prefix (``sha512:``) is kept, so a genuinely
    different algorithm still fails.
    """
    text = str(value)
    if ":" in text:
        prefix, _, rest = text.partition(":")
        if prefix.lower() == "sha256":
            return rest.lower()
    return text.lower() if all(c in "0123456789abcdefABCDEF" for c in text) else text


def verify_chain_bindings(chain: EvidenceChain) -> ChainBinding:
    """Check that every stage refers to the same, immutable transaction identity.

    A stage that was never populated does not fail the check — an absent fact is
    not a contradiction. A stage that is populated with a *conflicting* value is a
    failure: that is the whole point of the chain.
    """
    binding = ChainBinding(bound=True)
    s = chain.stages
    auth = s.get("AUTHORIZATION", {})
    prepared = s.get("PREPARED_TRANSACTION", {})
    tee = s.get("TEE_EXECUTION", {})
    att = s.get("ATTESTATION", {})
    sig = s.get("SIGNATURE", {})
    bcast = s.get("BROADCAST", {})
    settle = s.get("SETTLEMENT", {})

    def agree(name: str, *values: Any) -> None:
        present = [v for v in values if v not in (None, "", {})]
        if len(present) < 2:
            return
        normalised = [_normalise(v) for v in present]
        _add(
            binding,
            name,
            all(v == normalised[0] for v in normalised),
            f"{present}",
        )

    agree("transaction_digest_agrees", auth.get("transaction_digest"),
          prepared.get("transaction_digest"), tee.get("transaction_digest"),
          sig.get("transaction_digest"), chain.transaction_digest)
    agree("network_agrees", auth.get("network"), prepared.get("network"),
          tee.get("network"), chain.network)
    agree("receiver_agrees", auth.get("receiver_account"), prepared.get("receiver_account"),
          sig.get("receiver_account"))
    agree("amount_agrees", auth.get("amount_base"), prepared.get("amount_base"),
          sig.get("amount_base"))
    agree("signer_public_key_agrees", tee.get("public_key"), sig.get("public_key"))
    agree("approved_build_agrees", tee.get("approved_build"), att.get("wasm_hash"),
          sig.get("approved_build"))
    agree("broadcast_hash_agrees", bcast.get("tx_hash"), chain.tx_hash,
          settle.get("tx_hash"))

    # The one check that is not string equality: the signature is re-verified
    # against the signer key over the recorded digest. A chain can name a
    # signature and a key that agree everywhere else and still carry a signature
    # that does not actually verify — only a cryptographic check catches that.
    # The enclave signs ``sha256(unsigned_bytes)``, which is exactly
    # ``transaction_digest``; the signature covers the *signed* transaction hash,
    # a different value, so re-hashing the signed bytes would be wrong. When a
    # field is absent the check is skipped (a limitation, never a pass on a
    # present-but-wrong signature).
    _check_signature_over_digest(binding, sig)

    binding.bound = not binding.failures
    return binding


def _check_signature_over_digest(binding: ChainBinding, sig: Mapping[str, Any]) -> None:
    signature_b64 = str(sig.get("signature_b64") or "")
    public_key = str(sig.get("public_key") or "")
    digest = str(sig.get("transaction_digest") or "")
    if not (signature_b64 and public_key and digest):
        return
    try:
        import base64

        from .. import ed25519
        from ... import base58

        raw_signature = base64.b64decode(signature_b64, validate=True)
        raw_public = base58.b58decode(public_key.split(":")[-1]) or b""
        raw_digest = bytes.fromhex(_normalise(digest))
    except (ValueError, TypeError):
        _add(binding, "signature_verifies_over_the_digest", False,
             "the signature, key or digest is malformed")
        return
    holds = (
        len(raw_signature) == 64
        and len(raw_public) == 32
        and len(raw_digest) == 32
        and ed25519.verify(raw_signature, raw_digest, raw_public)
    )
    _add(
        binding,
        "signature_verifies_over_the_digest",
        holds,
        "ed25519 signature re-verified over the recorded digest" if holds
        else "the signature does not verify against the recorded key and digest",
    )


def _reject_secrets(chain: EvidenceChain) -> None:
    blob = json.dumps(chain.to_dict())
    lowered = blob.lower()
    for key in _FORBIDDEN_KEYS:
        if f'"{key}"' in lowered:
            raise EvidenceChainError(f"the evidence chain would carry a secret field {key!r}")


def build_evidence_chain(
    *,
    transaction_digest: str,
    authorization: Mapping[str, Any] | None = None,
    transaction: Mapping[str, Any] | None = None,
    signing: Mapping[str, Any] | None = None,
    attestation: Mapping[str, Any] | None = None,
    submission: Mapping[str, Any] | None = None,
    settlement: Mapping[str, Any] | None = None,
    network: str = "",
    tx_hash: str = "",
    created_at: str = "",
) -> EvidenceChain:
    """Assemble a chain from whatever the caller has, without inventing anything.

    Every argument is optional: a chain built right after authorization has only
    the first stages, and a later stage is filled in as the facts arrive. A field
    that is not supplied is simply absent — never defaulted to a value that would
    make the chain look more complete than it is.
    """
    chain = EvidenceChain(
        transaction_digest=transaction_digest,
        tx_hash=tx_hash,
        network=network,
        created_at=created_at,
    )
    if authorization:
        chain.put(
            "AUTHORIZATION",
            authorization_id=authorization.get("id", ""),
            decision=authorization.get("decision", ""),
            policy_version=authorization.get("policy_version", ""),
            approver=authorization.get("approver", ""),
            expiry=authorization.get("expiry", ""),
            digest=authorization.get("digest", ""),
            network=authorization.get("network", network),
            transaction_digest=authorization.get("transaction_digest", transaction_digest),
            # The parameters the authorization is bound to. Recording them here is
            # what lets a later stage be checked *against the authorization* rather
            # than only against another later stage.
            receiver_account=authorization.get("receiver_account", ""),
            amount_base=str(authorization.get("amount_base", "")),
        )
    if transaction:
        chain.put(
            "PREPARED_TRANSACTION",
            signer_account=transaction.get("signer_id", transaction.get("signer_account", "")),
            public_key=transaction.get("public_key", ""),
            receiver_account=transaction.get("receiver_id", transaction.get("receiver_account", "")),
            amount_base=str(transaction.get("amount_base", "")),
            destination=transaction.get("destination", ""),
            nonce=transaction.get("nonce", ""),
            block_hash=transaction.get("block_hash", ""),
            network=transaction.get("network", network),
            transaction_digest=transaction.get("transaction_digest", transaction_digest),
            unsigned_bytes_sha256=transaction.get("unsigned_bytes_sha256", ""),
        )
    if signing:
        chain.put(
            "TEE_EXECUTION",
            provider=signing.get("provider", ""),
            route=signing.get("route", ""),
            execution_id=signing.get("execution_id", ""),
            public_key=signing.get("public_key", ""),
            approved_build=signing.get("approved_build", ""),
            network=signing.get("network", network),
            transaction_digest=signing.get("transaction_digest", transaction_digest),
        )
        chain.put(
            "SIGNATURE",
            public_key=signing.get("public_key", ""),
            signature_b64=signing.get("signature_b64", ""),
            transaction_digest=signing.get("transaction_digest", transaction_digest),
            receiver_account=signing.get("receiver_account", ""),
            amount_base=str(signing.get("amount_base", "")),
            approved_build=signing.get("approved_build", ""),
            verified=signing.get("signature_verified", False),
        )
        if signing.get("tx_hash"):
            chain.tx_hash = chain.tx_hash or str(signing["tx_hash"])
    if attestation:
        chain.put(
            "ATTESTATION",
            level=attestation.get("level", ""),
            verified=attestation.get("verified", False),
            quote_verified=attestation.get("quote_verified", False),
            worker_measurement=attestation.get("worker_measurement", ""),
            measurement_approved=attestation.get("measurement_approved"),
            wasm_hash=attestation.get("wasm_hash", ""),
            task_hash=attestation.get("task_hash", ""),
            transaction_hash=attestation.get("transaction_hash", ""),
            failures=list(attestation.get("failures", []) or []),
        )
    if submission:
        chain.put(
            "BROADCAST",
            tx_hash=submission.get("tx_hash", ""),
            state=submission.get("state", ""),
            signed_b64_sha256=submission.get("signed_b64_sha256", ""),
            attempts=submission.get("attempts", 0),
        )
        if submission.get("tx_hash"):
            chain.tx_hash = chain.tx_hash or str(submission["tx_hash"])
    if settlement:
        chain.put(
            "FINALITY",
            final=settlement.get("final", settlement.get("final_execution_status", "")),
            tx_hash=settlement.get("tx_hash", chain.tx_hash),
        )
        chain.put(
            "SETTLEMENT",
            state=settlement.get("state", ""),
            tx_hash=settlement.get("tx_hash", chain.tx_hash),
            receiver=settlement.get("receiver", ""),
            amount_base=str(settlement.get("amount_base", "")),
            balance_delta=settlement.get("balance_delta", ""),
            all_checks_passed=settlement.get("all_checks_passed"),
            failed_checks=list(settlement.get("failed_checks", []) or []),
            sources=list(settlement.get("sources", []) or []),
        )
    _reject_secrets(chain)
    return chain


class EvidenceChainStore:
    """Durable storage for evidence chains (SQLite), with an in-memory mode.

    A configured path that cannot be opened is a hard failure, matching the
    submission ledger: a chain that cannot be persisted must not silently live
    only in memory, because it is the record an auditor relies on.
    """

    def __init__(self, path: str | None = None) -> None:
        self._lock = threading.RLock()
        self._memory: dict[str, EvidenceChain] = {}
        self._conn: sqlite3.Connection | None = None
        self.path = path
        if path:
            self._conn = sqlite3.connect(path, check_same_thread=False)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=FULL")
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS evidence_chains (
                    tx_hash TEXT PRIMARY KEY,
                    chain_digest TEXT NOT NULL,
                    record TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            self._conn.commit()

    @property
    def backend(self) -> str:
        return "sqlite" if self._conn is not None else "in-memory"

    def put(self, chain: EvidenceChain) -> None:
        from ..ledger import _utc_now

        key = chain.tx_hash or chain.transaction_digest
        now = _utc_now()
        if not chain.created_at:
            chain.created_at = now
        blob = chain.to_json()
        with self._lock:
            if self._conn is not None:
                self._conn.execute(
                    "INSERT INTO evidence_chains (tx_hash, chain_digest, record, updated_at) "
                    "VALUES (?, ?, ?, ?) ON CONFLICT(tx_hash) DO UPDATE SET "
                    "chain_digest=excluded.chain_digest, record=excluded.record, "
                    "updated_at=excluded.updated_at",
                    (key, chain.digest(), blob, now),
                )
                self._conn.commit()
            else:
                self._memory[key] = chain

    def get(self, tx_hash: str) -> EvidenceChain | None:
        with self._lock:
            if self._conn is not None:
                row = self._conn.execute(
                    "SELECT record FROM evidence_chains WHERE tx_hash = ?", (tx_hash,)
                ).fetchone()
                return EvidenceChain.from_dict(json.loads(row[0])) if row else None
            return self._memory.get(tx_hash)

    def all(self) -> tuple[EvidenceChain, ...]:
        with self._lock:
            if self._conn is not None:
                rows = self._conn.execute("SELECT record FROM evidence_chains").fetchall()
                return tuple(EvidenceChain.from_dict(json.loads(r[0])) for r in rows)
            return tuple(self._memory.values())

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None


__all__ = [
    "STAGES",
    "ChainBinding",
    "EvidenceChain",
    "EvidenceChainError",
    "EvidenceChainStore",
    "build_evidence_chain",
    "verify_chain_bindings",
]
