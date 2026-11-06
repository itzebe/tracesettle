"""Counterparty risk intelligence for agent payments.

Before an agent pays an account, it is worth asking what is actually known about
that account. This module gathers that from sources that are free, public and
independently checkable, and returns a deterministic :class:`CounterpartyRead`
that the agent-side wrapper folds into its decision.

Signals, and exactly where each comes from
------------------------------------------
* **Account existence** — ``query``/``view_account`` on the configured NEAR RPC.
  A JSON-RPC ``UNKNOWN_ACCOUNT`` is a definitive "does not exist", distinct from
  an outage.
* **Account type (contract vs user)** — the ``code_hash`` field of the same
  response. ``11111111111111111111111111111111`` is the protocol's "holds no
  contract" hash; any other value means a contract is deployed at that account.
* **Account age (lower bound)** — ``view_account`` reports the ``block_height``
  at which it was observed and ``block`` reports the head. The difference is a
  lower bound on age **in blocks**, which needs no trusted clock and no indexer.
* **Prior interactions with this agent** — the durable authorization replay store
  the guard already keeps. It counts how many authorizations this agent has spent
  to this destination. It is local, needs no network, and says so.
* **Shared blocklist** — an operator-supplied, evidence-backed list of
  ``(chain, address) -> evidence`` entries loaded from a file. Every entry
  carries a source and a note, so a block is explainable. **No list of real
  "bad" accounts is bundled**: labelling a real account malicious without
  evidence is the fabrication this project refuses to make.

Deliberately *not* used
-----------------------
* **Contract code-change history.** The RPC returns only the *current*
  ``code_hash``; there is no free, keyless endpoint that reports when code last
  changed. The public indexer ``api.nearblocks.io`` answers without a key but is
  rate-limited too aggressively to sit in a decision path. A signal that cannot
  be fetched reliably is worse than no signal, so it is not claimed. Where a
  contract is present the fact is reported, and an operator may pin an expected
  hash via the blocklist.
* **Any reputation score.** A score would be a number this module invented.

Failure policy
--------------
The mandatory controls are the guard's policy and the operator blocklist; those
never depend on the network. This module only *adds* restrictions, and every
uncertainty is surfaced as a finding rather than hidden:

* account does not exist -> ``BLOCK`` (a transfer to a non-existent account
  creates it, which is a real risk for an agent paying a typo);
* account is on the operator blocklist -> ``BLOCK``;
* account is a contract -> ``REVIEW`` (paying a contract is not paying a person);
* account is newer than the configured floor -> ``REVIEW``;
* a signal could not be read -> ``UNKNOWN``, which the wrapper treats as the
  strictest outcome. "Unknown" is never reported as "safe".
"""

from __future__ import annotations

import enum
import json
import pathlib
from dataclasses import dataclass, field
from typing import Any

from ..model import SourceStatus
from .rpc import NearRpc

#: The protocol's "this account holds no contract" code hash. Any other value
#: means a contract is deployed at the account.
NO_CONTRACT_HASH = "11111111111111111111111111111111"

#: How old (in blocks) an account must be to avoid a "new account" review. At
#: roughly one block per second this is about a day. It is a review trigger, not
#: a judgement, and an operator may raise or lower it.
DEFAULT_MIN_ACCOUNT_AGE_BLOCKS = 86_400

#: The name recorded for the RPC as a data source, for provenance.
RPC_SOURCE = "near-rpc:query/view_account"


class CounterpartyOutcome(str, enum.Enum):
    """The strictest thing the counterparty signals require."""

    CLEAR = "CLEAR"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"
    #: A required signal could not be read. Strictest: never treated as safe.
    UNKNOWN = "UNKNOWN"

    @property
    def rank(self) -> int:
        return _OUTCOME_RANK[self]


#: Ordered so a strictest-wins combination is a ``max``. UNKNOWN is strictest.
_OUTCOME_RANK = {
    CounterpartyOutcome.CLEAR: 0,
    CounterpartyOutcome.REVIEW: 1,
    CounterpartyOutcome.BLOCK: 2,
    CounterpartyOutcome.UNKNOWN: 3,
}


class SignalSeverity(str, enum.Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return _SIGNAL_RANK[self]


_SIGNAL_RANK = {
    SignalSeverity.INFO: 0,
    SignalSeverity.LOW: 1,
    SignalSeverity.MEDIUM: 2,
    SignalSeverity.HIGH: 3,
    SignalSeverity.CRITICAL: 4,
}


@dataclass(frozen=True)
class CounterpartyFinding:
    """One signal's result, with its source and the exact retrieval method."""

    code: str
    severity: SignalSeverity
    title: str
    detail: str
    source: str
    method: str
    observed: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity.value,
            "title": self.title,
            "detail": self.detail,
            "source": self.source,
            "method": self.method,
            "observed": dict(self.observed),
        }


@dataclass(frozen=True)
class BlocklistEntry:
    """One evidence-backed blocklist entry."""

    chain: str
    address: str
    source: str
    note: str

    def to_dict(self) -> dict[str, Any]:
        return {"chain": self.chain, "address": self.address, "source": self.source, "note": self.note}


class Blocklist:
    """An operator-supplied, evidence-backed blocklist.

    Every entry must name a source; an entry without evidence is refused at load
    time rather than silently accepted, so a block can always be explained.
    Matching is case-insensitive on both the chain and the address (NEAR named
    accounts are lowercase; hex addresses are case-insensitive).
    """

    def __init__(self, entries: tuple[BlocklistEntry, ...] = ()) -> None:
        self._entries = entries
        self._index: dict[tuple[str, str], BlocklistEntry] = {}
        for entry in entries:
            self._index[(entry.chain.strip().lower(), entry.address.strip().lower())] = entry

    def __len__(self) -> int:
        return len(self._entries)

    @property
    def entries(self) -> tuple[BlocklistEntry, ...]:
        return self._entries

    def match(self, *, chain: str, address: str) -> BlocklistEntry | None:
        return self._index.get((chain.strip().lower(), address.strip().lower()))

    @classmethod
    def from_file(cls, path: str | pathlib.Path) -> Blocklist:
        """Load a blocklist file, refusing any entry that carries no evidence."""
        raw = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or not isinstance(raw.get("entries"), list):
            raise ValueError("a blocklist file must be an object with an 'entries' list")
        entries: list[BlocklistEntry] = []
        for i, item in enumerate(raw["entries"]):
            if not isinstance(item, dict):
                raise ValueError(f"blocklist entry {i} must be an object")
            chain = str(item.get("chain", "")).strip()
            address = str(item.get("address", "")).strip()
            source = str(item.get("source", "")).strip()
            note = str(item.get("note", "")).strip()
            if not chain or not address:
                raise ValueError(f"blocklist entry {i} must name a chain and an address")
            if not source:
                raise ValueError(
                    f"blocklist entry {i} ({address}) carries no evidence source; "
                    "an unevidenced block is refused"
                )
            entries.append(BlocklistEntry(chain=chain, address=address, source=source, note=note))
        return cls(tuple(entries))


@dataclass(frozen=True)
class CounterpartyRead:
    """What is known about a counterparty, and what that implies."""

    account_id: str
    chain: str
    outcome: CounterpartyOutcome
    exists: bool | None = None
    is_contract: bool | None = None
    code_hash: str | None = None
    account_age_blocks: int | None = None
    min_account_age_blocks: int = DEFAULT_MIN_ACCOUNT_AGE_BLOCKS
    prior_interactions: int = 0
    blocklisted: BlocklistEntry | None = None
    findings: tuple[CounterpartyFinding, ...] = ()
    sources: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()

    @property
    def clear(self) -> bool:
        return self.outcome is CounterpartyOutcome.CLEAR

    def to_dict(self) -> dict[str, Any]:
        return {
            "account_id": self.account_id,
            "chain": self.chain,
            "outcome": self.outcome.value,
            "exists": self.exists,
            "is_contract": self.is_contract,
            "code_hash": self.code_hash,
            "account_age_blocks": self.account_age_blocks,
            "min_account_age_blocks": self.min_account_age_blocks,
            "prior_interactions": self.prior_interactions,
            "blocklisted": self.blocklisted.to_dict() if self.blocklisted else None,
            "findings": [f.to_dict() for f in self.findings],
            "sources": list(self.sources),
            "limitations": list(self.limitations),
        }


def _finding(
    code: str,
    severity: SignalSeverity,
    title: str,
    detail: str,
    *,
    source: str,
    method: str,
    observed: dict[str, str] | None = None,
) -> CounterpartyFinding:
    return CounterpartyFinding(
        code=code,
        severity=severity,
        title=title,
        detail=detail,
        source=source,
        method=method,
        observed=observed or {},
    )


class CounterpartyIntelligence:
    """Reads the free, public counterparty signals for one account.

    The only network access is the configured NEAR RPC. The blocklist and the
    prior-interaction count are local. Every read is deterministic for a given
    chain state.
    """

    def __init__(
        self,
        rpc: NearRpc,
        *,
        chain: str,
        blocklist: Blocklist | None = None,
        min_account_age_blocks: int = DEFAULT_MIN_ACCOUNT_AGE_BLOCKS,
    ) -> None:
        self.rpc = rpc
        self.chain = chain
        self.blocklist = blocklist
        self.min_account_age_blocks = min_account_age_blocks

    def read(self, account_id: str, *, prior_interactions: int = 0) -> CounterpartyRead:
        """Read every signal for ``account_id`` and combine them, strictest wins."""
        account_id = account_id.strip()
        findings: list[CounterpartyFinding] = []
        sources: list[str] = []
        limitations: list[str] = []
        proposed: list[CounterpartyOutcome] = []

        # 1. The operator blocklist. Local, evidence-backed, and the one signal
        #    that can hard-block without the network.
        blocklisted = None
        if self.blocklist is not None:
            blocklisted = self.blocklist.match(chain=self.chain, address=account_id)
        if blocklisted is not None:
            findings.append(
                _finding(
                    "COUNTERPARTY_BLOCKLISTED",
                    SignalSeverity.CRITICAL,
                    "Counterparty is on the operator blocklist",
                    f"{account_id} is blocklisted with evidence: {blocklisted.note}",
                    source=blocklisted.source,
                    method="operator blocklist file, exact (chain, address) match",
                    observed={"address": account_id, "chain": self.chain},
                )
            )
            proposed.append(CounterpartyOutcome.BLOCK)
            sources.append(blocklisted.source)
        elif self.blocklist is not None:
            sources.append("operator blocklist file")

        # 2. Account existence, type and age, from one RPC read.
        account = self.rpc.view_account(account_id)
        exists: bool | None = None
        is_contract: bool | None = None
        code_hash: str | None = None
        age_blocks: int | None = None

        if account.status is SourceStatus.NOT_FOUND:
            exists = False
            findings.append(
                _finding(
                    "COUNTERPARTY_DOES_NOT_EXIST",
                    SignalSeverity.HIGH,
                    "Counterparty account does not exist",
                    f"The network has no account {account_id}. A transfer to a non-existent "
                    "account creates it, so paying an unknown address can fund a new account "
                    "rather than a known counterparty.",
                    source=RPC_SOURCE,
                    method="JSON-RPC query view_account; error UNKNOWN_ACCOUNT",
                    observed={"address": account_id},
                )
            )
            proposed.append(CounterpartyOutcome.BLOCK)
            sources.append(RPC_SOURCE)
        elif not account.ok or not isinstance(account.data, dict):
            # We could not learn anything. Never "safe".
            findings.append(
                _finding(
                    "COUNTERPARTY_LOOKUP_UNAVAILABLE",
                    SignalSeverity.HIGH,
                    "Counterparty lookup could not be completed",
                    f"The NEAR RPC did not answer the account lookup for {account_id} "
                    f"(source status {account.status.value}). The counterparty could not be "
                    "checked, so it is not treated as safe.",
                    source=RPC_SOURCE,
                    method="JSON-RPC query view_account",
                    observed={"address": account_id, "source_status": account.status.value},
                )
            )
            proposed.append(CounterpartyOutcome.UNKNOWN)
            sources.append(RPC_SOURCE)
        else:
            exists = True
            code_hash = str(account.data.get("code_hash") or "") or None
            is_contract = code_hash is not None and code_hash != NO_CONTRACT_HASH
            sources.append(RPC_SOURCE)

            head = self.rpc.block_hash(finality="final")
            observed_height = account.data.get("block_height")
            if head.ok and isinstance(head.data, dict) and isinstance(head.data.get("height"), int) \
                    and isinstance(observed_height, int):
                age_blocks = max(0, int(head.data["height"]) - int(observed_height))
            else:
                limitations.append(
                    "The account's age could not be established (the head block height was "
                    "unavailable), so the age signal was not evaluated."
                )

            if is_contract:
                findings.append(
                    _finding(
                        "COUNTERPARTY_IS_CONTRACT",
                        SignalSeverity.MEDIUM,
                        "Counterparty is a contract, not a user account",
                        f"{account_id} has a deployed contract (code_hash {code_hash}). Paying a "
                        "contract is not the same as paying a person; a human should confirm the "
                        "intent before an agent signs.",
                        source=RPC_SOURCE,
                        method="JSON-RPC query view_account; code_hash differs from the no-contract hash",
                        observed={"address": account_id, "code_hash": str(code_hash)},
                    )
                )
                proposed.append(CounterpartyOutcome.REVIEW)
            elif code_hash is not None:
                findings.append(
                    _finding(
                        "COUNTERPARTY_IS_USER_ACCOUNT",
                        SignalSeverity.INFO,
                        "Counterparty is a user account",
                        f"{account_id} holds no contract (code_hash {NO_CONTRACT_HASH}).",
                        source=RPC_SOURCE,
                        method="JSON-RPC query view_account; code_hash equals the no-contract hash",
                        observed={"address": account_id},
                    )
                )

            if age_blocks is not None:
                if age_blocks < self.min_account_age_blocks:
                    findings.append(
                        _finding(
                            "COUNTERPARTY_ACCOUNT_IS_NEW",
                            SignalSeverity.MEDIUM,
                            "Counterparty account is new",
                            f"{account_id} is at most {age_blocks} blocks old, below the "
                            f"{self.min_account_age_blocks}-block review floor. A brand-new "
                            "account is a common destination for a redirected payment.",
                            source=RPC_SOURCE,
                            method="block height at account observation minus current head height",
                            observed={
                                "address": account_id,
                                "account_age_blocks": str(age_blocks),
                                "floor": str(self.min_account_age_blocks),
                            },
                        )
                    )
                    proposed.append(CounterpartyOutcome.REVIEW)
                else:
                    findings.append(
                        _finding(
                            "COUNTERPARTY_ACCOUNT_IS_ESTABLISHED",
                            SignalSeverity.INFO,
                            "Counterparty account is established",
                            f"{account_id} is at least {age_blocks} blocks old.",
                            source=RPC_SOURCE,
                            method="block height at account observation minus current head height",
                            observed={"address": account_id, "account_age_blocks": str(age_blocks)},
                        )
                    )

        # 3. Prior interactions. Local to this agent; informational only. A
        #    first-time payee is normal, so it never blocks or reviews by itself.
        findings.append(
            _finding(
                "COUNTERPARTY_PRIOR_INTERACTIONS",
                SignalSeverity.INFO if prior_interactions > 0 else SignalSeverity.LOW,
                "Prior interactions with this counterparty",
                f"This agent has {prior_interactions} prior spent authorization(s) to "
                f"{account_id} recorded locally.",
                source="local authorization replay store",
                method="count of consumed authorizations for this agent and destination",
                observed={"address": account_id, "prior_interactions": str(prior_interactions)},
            )
        )
        sources.append("local authorization replay store")

        outcome = max(proposed, key=lambda o: o.rank) if proposed else CounterpartyOutcome.CLEAR
        return CounterpartyRead(
            account_id=account_id,
            chain=self.chain,
            outcome=outcome,
            exists=exists,
            is_contract=is_contract,
            code_hash=code_hash,
            account_age_blocks=age_blocks,
            min_account_age_blocks=self.min_account_age_blocks,
            prior_interactions=prior_interactions,
            blocklisted=blocklisted,
            findings=tuple(findings),
            sources=tuple(dict.fromkeys(sources)),
            limitations=tuple(limitations),
        )
