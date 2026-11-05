"""Counterparty risk intelligence tests.

The reader's only network boundary is the NEAR RPC; a :class:`FakeRpc` supplies
recorded ``view_account``/``block`` results so every line of ``counterparty.py``
runs. No test makes a network call.
"""

from __future__ import annotations

import json

import pytest

from tracesettle.model import SourceStatus
from tracesettle.near.counterparty import (
    NO_CONTRACT_HASH,
    Blocklist,
    CounterpartyIntelligence,
    CounterpartyOutcome,
)
from tracesettle.near.rpc import RpcResult

ACCOUNT = "alice.near"
OTHER = "bob.near"


class FakeRpc:
    """A NEAR RPC transport that returns supplied account/head results."""

    def __init__(
        self,
        *,
        account: RpcResult | None = None,
        head_height: int | None = 2_000_000,
        head_ok: bool = True,
    ) -> None:
        self._account = account
        self._head_height = head_height
        self._head_ok = head_ok

    def view_account(self, account_id: str) -> RpcResult:
        if self._account is not None:
            return self._account
        return RpcResult(
            SourceStatus.OK,
            {"code_hash": NO_CONTRACT_HASH, "block_height": 1_900_000},
        )

    def block_hash(self, *, finality: str = "final") -> RpcResult:
        if not self._head_ok or self._head_height is None:
            return RpcResult(SourceStatus.TIMEOUT, error="head unavailable")
        return RpcResult(SourceStatus.OK, {"height": self._head_height})


def _reader(**kwargs) -> CounterpartyIntelligence:
    return CounterpartyIntelligence(FakeRpc(**kwargs), chain="near", min_account_age_blocks=86400)


def test_missing_account_is_blocked():
    read = _reader(account=RpcResult(SourceStatus.NOT_FOUND, error="UNKNOWN_ACCOUNT")).read(ACCOUNT)
    assert read.outcome is CounterpartyOutcome.BLOCK
    assert read.exists is False
    assert any(f.code == "COUNTERPARTY_DOES_NOT_EXIST" for f in read.findings)


def test_unreadable_lookup_is_unknown_never_clear():
    read = _reader(account=RpcResult(SourceStatus.TIMEOUT, error="timeout")).read(ACCOUNT)
    assert read.outcome is CounterpartyOutcome.UNKNOWN
    assert read.exists is None
    assert any(f.code == "COUNTERPARTY_LOOKUP_UNAVAILABLE" for f in read.findings)


def test_user_account_is_clear_when_established():
    read = _reader().read(ACCOUNT)
    assert read.outcome is CounterpartyOutcome.CLEAR
    assert read.is_contract is False
    assert read.account_age_blocks == 100_000


def test_contract_account_requires_review():
    read = _reader(
        account=RpcResult(SourceStatus.OK, {"code_hash": "abc123", "block_height": 1_900_000})
    ).read(ACCOUNT)
    assert read.outcome is CounterpartyOutcome.REVIEW
    assert read.is_contract is True


def test_new_account_requires_review():
    read = _reader(
        account=RpcResult(SourceStatus.OK, {"code_hash": NO_CONTRACT_HASH, "block_height": 1_999_900})
    ).read(ACCOUNT)
    assert read.outcome is CounterpartyOutcome.REVIEW
    assert any(f.code == "COUNTERPARTY_ACCOUNT_IS_NEW" for f in read.findings)


def test_unknown_head_is_a_limitation_not_a_verdict():
    read = _reader(head_ok=False).read(ACCOUNT)
    assert read.outcome is CounterpartyOutcome.CLEAR
    assert read.account_age_blocks is None
    assert any("age could not be established" in lim for lim in read.limitations)


def test_blocklisted_account_is_blocked_with_evidence():
    blocklist = Blocklist.from_file(_write_blocklist(ACCOUNT))
    read = CounterpartyIntelligence(
        FakeRpc(), chain="near", blocklist=blocklist
    ).read(ACCOUNT)
    assert read.outcome is CounterpartyOutcome.BLOCK
    assert read.blocklisted is not None
    assert read.blocklisted.source


def test_blocklist_match_is_case_insensitive_on_hex():
    blocklist = Blocklist.from_file(_write_blocklist("0xAbCd"))
    assert blocklist.match(chain="near", address="0xabcd") is not None


def test_blocklist_refuses_an_unevidenced_entry(tmp_path):
    path = tmp_path / "blocklist.json"
    path.write_text(json.dumps({"entries": [{"chain": "near", "address": ACCOUNT}]}))
    with pytest.raises(ValueError, match="no evidence source"):
        Blocklist.from_file(path)


def test_unknown_outcome_outranks_block():
    # A strictest-wins check: UNKNOWN is stricter than BLOCK in the ordering the
    # module documents, so a caller cannot treat a blocked-and-unreadable account
    # as merely blocked.
    assert CounterpartyOutcome.UNKNOWN.rank > CounterpartyOutcome.BLOCK.rank
    assert CounterpartyOutcome.BLOCK.rank > CounterpartyOutcome.REVIEW.rank
    assert CounterpartyOutcome.REVIEW.rank > CounterpartyOutcome.CLEAR.rank


def _write_blocklist(address: str):
    import tempfile
    from pathlib import Path

    d = Path(tempfile.mkdtemp())
    path = d / "blocklist.json"
    path.write_text(
        json.dumps(
            {
                "entries": [
                    {
                        "chain": "near",
                        "address": address,
                        "source": "https://example.invalid/report/1",
                        "note": "synthetic test entry",
                    }
                ]
            }
        )
    )
    return path
