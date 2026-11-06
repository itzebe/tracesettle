"""Intel PCS collateral validation for TDX attestation, standard-library only.

A TDX quote alone proves a genuine Intel-signed measurement was produced, but it
does **not** prove the platform's TCB is current or that the PCK certificate is
still trusted. Those facts live in Intel's Provisioning Certification Service
(PCS) collateral:

* the **TCB Info** for the platform's FMSPC, signed by the Intel SGX TCB Signing
  CA, which states the acceptable TCB component levels and the resulting status
  (``UpToDate`` / ``OutOfDate`` / ``SWHardeningNeeded`` / ``ConfigurationNeeded``
  / ``Revoked`` ...);
* the **PCK CRL**, signed by the Intel SGX Processor CA, which lists revoked PCK
  certificate serial numbers;
* the **QE Identity**, signed by the Intel SGX TCB Signing CA, which pins the
  acceptable Quoting Enclave identity (MRSIGNER, ISVPRODID, and the QE's own TCB).

Every collateral document is verified the same way the quote is: the exact bytes
Intel signed are located (Intel signs the raw JSON substring of the document,
not a re-serialisation), the signature is checked with ECDSA-P256-SHA256 under a
certificate from the issuer chain delivered in the response header, and that
chain is walked to the **pinned** Intel SGX Root CA.

What this module refuses to do:

* it never treats a *re-serialised* document as the signed bytes;
* it never accepts collateral whose issuer chain does not reach the pinned root;
* it never treats a TCB level as acceptable when the platform's components exceed
  it, nor when the level's ``tcbStatus`` is ``Revoked``;
* it never treats a stale (past ``nextUpdate``) document as current;
* it fails closed (``UNAVAILABLE``) when the collateral service cannot be reached,
  and it never substitutes cached collateral that has passed its freshness bound.

Nothing here invents an endpoint: the URLs are Intel's documented PCS v4 paths.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

from . import p256, tdx

#: Intel Provisioning Certification Service v4 base URLs (documented, public, no key).
#: TDX quotes are covered by the ``tdx`` service; the PCK CRL is shared and served
#: only under the ``sgx`` service (the ``tdx`` CRL path returns 404).
TDX_PCS_BASE_URL = "https://api.trustedservices.intel.com/tdx/certification/v4"
SGX_PCS_BASE_URL = "https://api.trustedservices.intel.com/sgx/certification/v4"
PCS_BASE_URL = TDX_PCS_BASE_URL

#: The documented issuer-chain response headers, one per collateral document.
_TCB_ISSUER_HEADER = "TCB-Info-Issuer-Chain"
_PCKCRL_ISSUER_HEADER = "SGX-PCK-CRL-Issuer-Chain"
_QE_ISSUER_HEADER = "SGX-Enclave-Identity-Issuer-Chain"

#: TCB statuses that a relying party must treat as unacceptable for a platform it
#: intends to trust. ``UpToDate`` and ``SWHardeningNeeded`` are acceptable (the
#: latter means the platform needs software hardening that the attester applies);
#: everything else means the TCB is out of date, mis-configured, or revoked.
UNACCEPTABLE_TCB_STATUSES = frozenset(
    {"Revoked", "OutOfDate", "OutOfDateConfigurationNeeded", "ConfigurationNeeded"}
)


class CollateralError(ValueError):
    """Collateral could not be validated."""


@dataclass(frozen=True)
class PckExtension:
    """The SGX extensions parsed from a PCK leaf certificate."""

    fmspc: str
    #: TCB component SVNs keyed by component index 1..16, plus 17 for the PCESVN.
    components: dict[int, int]
    pcesvn: int
    sgx_type: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "fmspc": self.fmspc,
            "components": dict(self.components),
            "pcesvn": self.pcesvn,
            "sgx_type": self.sgx_type,
        }


def _strip_octet_string(raw: bytes) -> bytes:
    reader = p256._DerReader(raw)
    return reader.read(0x04)


def parse_pck_extensions(cert: p256.Certificate) -> PckExtension:
    """Parse the SGX extensions (OID 1.2.840.113741.1.13.1) from a PCK certificate.

    Raises :class:`CollateralError` when the extension is absent or malformed; a
    PCK certificate without the extension cannot be used to derive an FMSPC.
    """
    reader = p256._DerReader(cert.tbs_der)
    inner = p256._DerReader(reader.read_sequence())
    if inner.peek_tag() == 0xA0:
        inner.read_raw_tlv()  # version
    inner.read_integer()  # serialNumber
    inner.read_raw_tlv()  # signature AlgorithmIdentifier
    inner.read_raw_tlv()  # issuer
    inner.read_sequence()  # validity
    inner.read_raw_tlv()  # subject
    inner.read_raw_tlv()  # subjectPublicKeyInfo
    extension_wrapper = None
    while not inner.exhausted:
        if inner.peek_tag() == 0xA3:
            extension_wrapper = inner.read_raw_tlv()
            break
        inner.read_raw_tlv()
    if extension_wrapper is None:
        raise CollateralError("PCK certificate has no extensions")

    extension_list = p256._DerReader(extension_wrapper).read(0xA3)
    extensions = p256._DerReader(p256._DerReader(extension_list).read_sequence())
    sgx_octets = None
    while not extensions.exhausted:
        entry = p256._DerReader(extensions.read_sequence())
        oid = entry.read_oid()
        if entry.peek_tag() == 0x01:
            entry.read_raw_tlv()  # critical flag
        value = _strip_octet_string(entry.read_raw_tlv())
        if oid == "1.2.840.113741.1.13.1":
            sgx_octets = value
    if sgx_octets is None:
        raise CollateralError("PCK certificate has no SGX extension")

    body = p256._DerReader(p256._DerReader(sgx_octets).read_sequence())
    fmspc = ""
    components: dict[int, int] = {}
    sgx_type = ""
    while not body.exhausted:
        sub = p256._DerReader(body.read_sequence())
        oid = sub.read_oid()
        if oid == "1.2.840.113741.1.13.1.4":
            fmspc = _strip_octet_string(sub.read_raw_tlv()).hex().upper()
        elif oid == "1.2.840.113741.1.13.1.2":
            tcb = p256._DerReader(p256._DerReader(sub.read_raw_tlv()).read(0x30))
            while not tcb.exhausted:
                comp = p256._DerReader(tcb.read_sequence())
                comp_oid = comp.read_oid()
                index = int(comp_oid.rsplit(".", 1)[-1])
                if comp.peek_tag() == 0x02:
                    components[index] = comp.read_integer()
                else:
                    comp.read_raw_tlv()
        elif oid == "1.2.840.113741.1.13.1.5":
            # sgxType is an ENUMERATED; keep its raw bytes rather than its integer.
            sgx_type = sub.read_raw_tlv().hex()
        else:
            sub.read_raw_tlv()
    if not fmspc:
        raise CollateralError("PCK certificate SGX extension has no FMSPC")
    pcesvn = components.pop(17, 0)
    return PckExtension(fmspc=fmspc, components=components, pcesvn=pcesvn, sgx_type=sgx_type)


def _locate_signed_document(raw: bytes, key: str) -> bytes:
    """Return the exact JSON substring Intel signed for ``key`` (a top-level object).

    Intel signs the literal bytes of the document value, so the byte range is
    located in the raw response and returned verbatim; re-serialising would change
    the bytes and invalidate the signature.
    """
    marker = ('"%s":' % key).encode("ascii")
    start = raw.find(marker)
    if start < 0:
        raise CollateralError(f"collateral has no {key!r} field")
    start += len(marker)
    while start < len(raw) and raw[start : start + 1] in (b" ", b"\n", b"\r", b"\t"):
        start += 1
    if raw[start : start + 1] != b"{":
        raise CollateralError(f"collateral {key!r} is not an object")
    depth = 0
    index = start
    while index < len(raw):
        byte = raw[index : index + 1]
        if byte == b"{":
            depth += 1
        elif byte == b"}":
            depth -= 1
            if depth == 0:
                return raw[start : index + 1]
        index += 1
    raise CollateralError(f"collateral {key!r} object is not terminated")


def _issuer_chain(header_value: str) -> tuple[p256.Certificate, ...]:
    pem = urllib.parse.unquote(header_value)
    return tdx._parse_pem_chain(pem.encode("ascii", "replace"))


def _verify_issuer_chain(
    chain: tuple[p256.Certificate, ...], *, expected_root_fingerprint: str
) -> bool:
    if len(chain) < 1:
        return False
    for child, issuer in zip(chain, chain[1:]):
        if not p256.verify_certificate_signature(child, issuer):
            return False
    root = chain[-1]
    if not p256.verify_certificate_signature(root, root):
        return False
    return root.fingerprint_sha256.hex() == expected_root_fingerprint


def verify_signed_document(
    raw: bytes,
    *,
    key: str,
    signature_hex: str,
    issuer_chain_header: str,
    expected_root_fingerprint: str,
) -> tuple[dict[str, Any], tuple[p256.Certificate, ...]]:
    """Verify a signed PCS collateral document and return its parsed body + chain."""
    signed_bytes = _locate_signed_document(raw, key)
    try:
        signature = bytes.fromhex(signature_hex)
    except ValueError as exc:
        raise CollateralError(f"collateral signature is not hex: {exc}") from exc
    chain = _issuer_chain(issuer_chain_header)
    if not _verify_issuer_chain(chain, expected_root_fingerprint=expected_root_fingerprint):
        raise CollateralError("collateral issuer chain does not reach the pinned Intel root")
    if not tdx.verify_ecdsa_raw(chain[0].public_key, signed_bytes, signature):
        raise CollateralError("collateral signature does not verify under the issuer chain leaf")
    try:
        body = json.loads(signed_bytes)
    except json.JSONDecodeError as exc:  # pragma: no cover - signed bytes came from JSON
        raise CollateralError(f"collateral document is not valid JSON: {exc}") from exc
    return body, chain


# --- TCB level evaluation -----------------------------------------------------


def evaluate_tcb_level(
    tcb_info: dict[str, Any], platform: PckExtension
) -> tuple[str, str, bool]:
    """Match ``platform`` against ``tcb_info``'s levels.

    Returns ``(status, tcb_date, acceptable)``. The Intel rule: walk the levels in
    order and pick the first whose every component SVN is ``<=`` the platform's and
    whose PCESVN is ``<=`` the platform's; that level's status applies. No level
    matching means the platform is newer than any known level, which is treated as
    ``OutOfDate``/unacceptable rather than silently accepted.
    """
    levels = tcb_info.get("tcbLevels") or []
    for level in levels:
        tcb = level.get("tcb") or {}
        level_components = tcb.get("sgxtcbcomponents") or []
        matches = True
        for index, component in enumerate(level_components, start=1):
            if platform.components.get(index, 0) < int(component.get("svn", 0)):
                matches = False
                break
        if matches and platform.pcesvn < int(tcb.get("pcesvn", 0)):
            matches = False
        if matches:
            status = str(level.get("tcbStatus", "Unknown"))
            return status, str(level.get("tcbDate", "")), status not in UNACCEPTABLE_TCB_STATUSES
    return "OutOfDate", "", False


# --- CRL parsing --------------------------------------------------------------


def parse_crl_revoked_serials(crl_der: bytes) -> tuple[set[int], dict[str, Any]]:
    """Parse an X.509 CRL and return its revoked serial numbers and metadata.

    Minimal, dependency-free DER parse: it reads the revokedCertificates list (a
    SEQUENCE of SEQUENCEs whose first element is the serialNumber) and the
    thisUpdate/nextUpdate times. Anything malformed raises :class:`CollateralError`.
    """
    reader = p256._DerReader(crl_der)
    body = p256._DerReader(reader.read_sequence())
    tbs = p256._DerReader(body.read_sequence())
    tbs.read_raw_tlv()  # version (optional)
    tbs.read_raw_tlv()  # signature AlgorithmIdentifier
    tbs.read_raw_tlv()  # issuer
    this_update = tbs.read_raw_tlv()  # thisUpdate
    next_update = b""
    if tbs.peek_tag() in (0x17, 0x18):
        next_update = tbs.read_raw_tlv()
    revoked: set[int] = set()
    if not tbs.exhausted and tbs.peek_tag() == 0x30:
        entries = p256._DerReader(tbs.read_sequence())
        while not entries.exhausted:
            entry = p256._DerReader(entries.read_sequence())
            revoked.add(entry.read_integer())
    metadata = {
        "this_update": _ts_to_iso(tdx._parse_asn1_time(p256._asn1_time(this_update))),
        "next_update": (
            _ts_to_iso(tdx._parse_asn1_time(p256._asn1_time(next_update)))
            if next_update
            else None
        ),
        "revoked_count": len(revoked),
    }
    return revoked, metadata


def _ts_to_iso(timestamp: int) -> str:
    import datetime

    return datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


# --- QE identity --------------------------------------------------------------


def evaluate_qe_identity(
    qe_identity: dict[str, Any], qe_report: bytes
) -> tuple[bool, str]:
    """Check the Quoting Enclave report against Intel's QE Identity document.

    The QE report (384 bytes) is an **SGX** report; the fields this check uses are
    MRSIGNER at [128:160], ISVPRODID at [256:258] and ISVSVN at [258:260]. (The
    TDX TD report uses different offsets; the QE report inside a TDX quote is an
    SGX report, so these offsets apply here.) Intel's TDX QE Identity states the
    accepted MRSIGNER, ISVPRODID and the ISVSVN levels, so a QE whose signer does
    not match the pinned identity, or whose ISVSVN is below every published level,
    is refused.
    """
    identity = qe_identity.get("enclaveIdentity") if "enclaveIdentity" in qe_identity else qe_identity
    if not isinstance(identity, dict):
        return False, "QE identity document has an unexpected shape"
    expected_mrsigner = str(identity.get("mrsigner", "")).lower()
    expected_prodid = int(identity.get("isvprodid", -1))
    if not expected_mrsigner or expected_prodid < 0:
        return False, "QE identity document is missing mrsigner/isvprodid"
    if len(qe_report) < 384:
        return False, "QE report is too short to read its identity"
    mrsigner = qe_report[128:160].hex()
    # ISVPRODID and ISVSVN are little-endian uint16 in the SGX report layout.
    isvprodid = int.from_bytes(qe_report[256:258], "little")
    isvsvn = int.from_bytes(qe_report[258:260], "little")
    if mrsigner != expected_mrsigner:
        return False, "QE report MRSIGNER does not match Intel's QE identity"
    if isvprodid != expected_prodid:
        return False, "QE report ISVPRODID does not match Intel's QE identity"
    levels = identity.get("tcbLevels") or []
    accepted = any(isvsvn >= int((level.get("tcb") or {}).get("isvsvn", 0)) for level in levels)
    if levels and not accepted:
        return False, f"QE report ISVSVN {isvsvn} is below every published QE TCB level"
    return True, "QE identity matches Intel's published QE identity"


# --- collateral fetch + cache -------------------------------------------------


@dataclass
class CollateralDocument:
    """One fetched-and-verified collateral document."""

    name: str
    url: str
    fetched: bool
    verified: bool
    detail: str
    body: dict[str, Any] | None = None
    chain_fingerprints: list[str] = field(default_factory=list)
    issue_date: str = ""
    next_update: str = ""
    fresh: bool = False
    from_cache: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "url": self.url,
            "fetched": self.fetched,
            "verified": self.verified,
            "detail": self.detail,
            "chain_fingerprints": list(self.chain_fingerprints),
            "issue_date": self.issue_date,
            "next_update": self.next_update,
            "fresh": self.fresh,
            "from_cache": self.from_cache,
        }


@dataclass
class CollateralBundle:
    """The three PCS documents plus the derived TCB verdict."""

    available: bool
    tcb: CollateralDocument
    pckcrl: CollateralDocument
    qe_identity: CollateralDocument
    tcb_status: str = ""
    tcb_date: str = ""
    tcb_acceptable: bool = False
    pck_revoked: bool = False
    qe_identity_ok: bool = False
    failures: list[str] = field(default_factory=list)

    @property
    def verified(self) -> bool:
        """True only when every document verified, the TCB is acceptable, the PCK
        certificate is not revoked, and the QE identity matches."""
        return (
            self.available
            and self.tcb.verified
            and self.pckcrl.verified
            and self.qe_identity.verified
            and self.tcb_acceptable
            and not self.pck_revoked
            and self.qe_identity_ok
            and not self.failures
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "verified": self.verified,
            "tcb_status": self.tcb_status,
            "tcb_date": self.tcb_date,
            "tcb_acceptable": self.tcb_acceptable,
            "pck_revoked": self.pck_revoked,
            "qe_identity_ok": self.qe_identity_ok,
            "failures": list(self.failures),
            "documents": {
                "tcb": self.tcb.to_dict(),
                "pckcrl": self.pckcrl.to_dict(),
                "qe_identity": self.qe_identity.to_dict(),
            },
        }


class _CacheEntry:
    __slots__ = ("document", "stored_at")

    def __init__(self, document: CollateralDocument, stored_at: float) -> None:
        self.document = document
        self.stored_at = stored_at


class PcsCollateralClient:
    """Fetches and validates Intel PCS collateral, with a bounded fresh cache.

    The client is deliberately conservative: a cached document is only reused
    within ``cache_ttl_seconds`` *and* while it is still before its own
    ``nextUpdate``. Past either bound it is refetched; if the refetch fails the
    client reports ``UNAVAILABLE`` rather than reusing stale material.
    """

    def __init__(
        self,
        *,
        base_url: str = PCS_BASE_URL,
        crl_base_url: str = SGX_PCS_BASE_URL,
        transport: Any = None,
        cache_ttl_seconds: int = 3600,
        expected_root_fingerprint: str = tdx.INTEL_SGX_ROOT_CA_SHA256,
        clock: Any = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.crl_base_url = crl_base_url.rstrip("/")
        self._transport = transport
        self.cache_ttl_seconds = max(0, int(cache_ttl_seconds))
        self.expected_root_fingerprint = expected_root_fingerprint
        self._clock = clock or time.time
        self._cache: dict[str, _CacheEntry] = {}
        self._lock = threading.Lock()

    # -- transport ---------------------------------------------------------

    def _get(self, url: str) -> tuple[bytes, dict[str, str]]:
        if self._transport is not None:
            return self._transport(url)
        import urllib.request

        with urllib.request.urlopen(url, timeout=20) as response:  # noqa: S310 - fixed https host
            raw = response.read()
            headers = {k: v for k, v in response.headers.items()}
        return raw, headers

    def _fetch_document(
        self, *, name: str, url: str, key: str, issuer_header: str
    ) -> CollateralDocument:
        try:
            raw, headers = self._get(url)
        except Exception as exc:  # noqa: BLE001 - any transport failure is "unavailable"
            return CollateralDocument(
                name=name,
                url=url,
                fetched=False,
                verified=False,
                detail=f"collateral fetch failed: {type(exc).__name__}",
            )
        header_value = ""
        for header_name, header_value_raw in headers.items():
            if header_name.lower() == issuer_header.lower():
                header_value = header_value_raw
                break
        if not header_value:
            return CollateralDocument(
                name=name,
                url=url,
                fetched=True,
                verified=False,
                detail=f"response has no {issuer_header} header",
            )
        try:
            body, chain = verify_signed_document(
                raw,
                key=key,
                signature_hex=_signature_field(raw),
                issuer_chain_header=header_value,
                expected_root_fingerprint=self.expected_root_fingerprint,
            )
        except CollateralError as exc:
            return CollateralDocument(
                name=name,
                url=url,
                fetched=True,
                verified=False,
                detail=str(exc),
            )
        document_body = body.get(key) if isinstance(body, dict) and key in body else body
        if not isinstance(document_body, dict):
            return CollateralDocument(
                name=name,
                url=url,
                fetched=True,
                verified=False,
                detail=f"collateral {key!r} is not an object",
            )
        return CollateralDocument(
            name=name,
            url=url,
            fetched=True,
            verified=True,
            detail="signature verified against the pinned Intel root",
            body=document_body,
            chain_fingerprints=[c.fingerprint_sha256.hex() for c in chain],
            issue_date=str(document_body.get("issueDate", "")),
            next_update=str(document_body.get("nextUpdate", "")),
        )

    def _cached(self, name: str) -> CollateralDocument | None:
        with self._lock:
            entry = self._cache.get(name)
        if entry is None:
            return None
        if self._clock() - entry.stored_at > self.cache_ttl_seconds:
            return None
        if not _is_fresh(entry.document.next_update, now=self._clock()):
            return None
        cached = entry.document
        return CollateralDocument(**{**cached.__dict__, "from_cache": True})

    def _store(self, document: CollateralDocument) -> None:
        if document.verified:
            with self._lock:
                self._cache[document.name] = _CacheEntry(document, self._clock())

    # -- the three documents ----------------------------------------------

    def tcb_info(self, fmspc: str) -> CollateralDocument:
        name = f"tcb:{fmspc}"
        cached = self._cached(name)
        if cached is not None:
            return cached
        url = f"{self.base_url}/tcb?fmspc={urllib.parse.quote(fmspc)}"
        document = self._fetch_document(
            name=name, url=url, key="tcbInfo", issuer_header=_TCB_ISSUER_HEADER
        )
        self._store(document)
        return document

    def pck_crl(self, *, ca: str = "processor", encoding: str = "der") -> CollateralDocument:
        name = f"pckcrl:{ca}:{encoding}"
        cached = self._cached(name)
        if cached is not None:
            return cached
        url = f"{self.crl_base_url}/pckcrl?ca={urllib.parse.quote(ca)}&encoding={urllib.parse.quote(encoding)}"
        if encoding == "der":
            # A DER CRL is not JSON; fetch it raw and verify the issuer chain only,
            # because the CRL is self-authenticating (its signature covers its TBS).
            document = self._fetch_crl(name=name, url=url)
        else:
            document = self._fetch_document(
                name=name, url=url, key="pckCrl", issuer_header=_PCKCRL_ISSUER_HEADER
            )
        self._store(document)
        return document

    def _fetch_crl(self, *, name: str, url: str) -> CollateralDocument:
        try:
            raw, headers = self._get(url)
        except Exception as exc:  # noqa: BLE001
            return CollateralDocument(
                name=name,
                url=url,
                fetched=False,
                verified=False,
                detail=f"collateral fetch failed: {type(exc).__name__}",
            )
        header_value = ""
        for header_name, header_value_raw in headers.items():
            if header_name.lower() == _PCKCRL_ISSUER_HEADER.lower():
                header_value = header_value_raw
                break
        if not header_value:
            return CollateralDocument(
                name=name,
                url=url,
                fetched=True,
                verified=False,
                detail=f"response has no {_PCKCRL_ISSUER_HEADER} header",
            )
        chain = _issuer_chain(header_value)
        if not _verify_issuer_chain(chain, expected_root_fingerprint=self.expected_root_fingerprint):
            return CollateralDocument(
                name=name,
                url=url,
                fetched=True,
                verified=False,
                detail="CRL issuer chain does not reach the pinned Intel root",
            )
        try:
            revoked, metadata = parse_crl_revoked_serials(raw)
        except (CollateralError, p256.P256Error) as exc:
            return CollateralDocument(
                name=name,
                url=url,
                fetched=True,
                verified=False,
                detail=f"CRL could not be parsed: {exc}",
            )
        # The CRL's own signature must verify under the issuer chain leaf.
        crl_signature_ok = _verify_crl_signature(raw, chain[0])
        if not crl_signature_ok:
            return CollateralDocument(
                name=name,
                url=url,
                fetched=True,
                verified=False,
                detail="CRL signature does not verify under its issuer chain leaf",
            )
        return CollateralDocument(
            name=name,
            url=url,
            fetched=True,
            verified=True,
            detail="CRL signature and issuer chain verified",
            body={"revoked_serials": sorted(revoked), **metadata},
            chain_fingerprints=[c.fingerprint_sha256.hex() for c in chain],
            issue_date=str(metadata.get("this_update", "")),
            next_update=str(metadata.get("next_update") or ""),
        )

    def qe_identity(self, *, update: str = "standard") -> CollateralDocument:
        name = f"qeidentity:{update}"
        cached = self._cached(name)
        if cached is not None:
            return cached
        url = f"{self.base_url}/qe/identity?update={urllib.parse.quote(update)}"
        document = self._fetch_document(
            name=name, url=url, key="enclaveIdentity", issuer_header=_QE_ISSUER_HEADER
        )
        self._store(document)
        return document


def _signature_field(raw: bytes) -> str:
    """Extract the top-level ``signature`` hex string from a PCS JSON response."""
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CollateralError(f"collateral response is not valid JSON: {exc}") from exc
    signature = parsed.get("signature")
    if not isinstance(signature, str):
        raise CollateralError("collateral response has no signature field")
    return signature


def _verify_crl_signature(crl_der: bytes, issuer: p256.Certificate) -> bool:
    reader = p256._DerReader(crl_der)
    body = p256._DerReader(reader.read_sequence())
    tbs_der = body.read_raw_tlv()
    body.read_raw_tlv()  # signatureAlgorithm
    signature = body.read_bit_string()
    return p256.verify_signature(issuer.public_key, tbs_der, signature)


def _is_fresh(next_update: str, *, now: float) -> bool:
    """True when ``next_update`` (ISO-8601 Z) is still in the future."""
    if not next_update:
        return False
    try:
        cleaned = next_update.strip().replace("Z", "+00:00")
        parsed = _parse_iso(cleaned)
    except (ValueError, TypeError):
        return False
    return parsed > now


def _parse_iso(value: str) -> float:
    import datetime

    text = value
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    return datetime.datetime.fromisoformat(text).timestamp()


def validate_collateral(
    client: PcsCollateralClient,
    *,
    pck_leaf: p256.Certificate,
    qe_report: bytes,
    now: float | None = None,
) -> CollateralBundle:
    """Fetch and validate the full PCS collateral set for a quote's PCK leaf.

    Fails closed: when the collateral service is unavailable, the bundle reports
    ``available=False`` and ``verified=False`` and the caller must refuse
    TEE-required execution.
    """
    clock = time.time if now is None else lambda: now
    try:
        extension = parse_pck_extensions(pck_leaf)
    except (CollateralError, p256.P256Error) as exc:
        return CollateralBundle(
            available=False,
            tcb=CollateralDocument("tcb", "", False, False, f"PCK extension parse failed: {exc}"),
            pckcrl=CollateralDocument("pckcrl", "", False, False, "not attempted"),
            qe_identity=CollateralDocument("qe_identity", "", False, False, "not attempted"),
            failures=[f"PCK extension parse failed: {exc}"],
        )

    tcb_document = client.tcb_info(extension.fmspc)
    crl_document = client.pck_crl(ca="processor", encoding="der")
    qe_document = client.qe_identity(update="standard")

    failures: list[str] = []
    for document in (tcb_document, crl_document, qe_document):
        if not document.verified:
            failures.append(f"{document.name}: {document.detail}")

    tcb_status = ""
    tcb_date = ""
    tcb_acceptable = False
    if tcb_document.verified and tcb_document.body is not None:
        tcb_status, tcb_date, tcb_acceptable = evaluate_tcb_level(tcb_document.body, extension)
        if not tcb_acceptable:
            failures.append(f"TCB status {tcb_status!r} is not acceptable")
        if not _is_fresh(tcb_document.next_update, now=clock()):
            failures.append("TCB info collateral is stale (past nextUpdate)")
            tcb_acceptable = False

    pck_revoked = False
    if crl_document.verified and crl_document.body is not None:
        serials = set(crl_document.body.get("revoked_serials", []))
        leaf_serial = _certificate_serial(pck_leaf)
        pck_revoked = leaf_serial in serials
        if pck_revoked:
            failures.append("PCK certificate is revoked")
        if not _is_fresh(crl_document.next_update, now=clock()):
            failures.append("PCK CRL collateral is stale (past nextUpdate)")
            pck_revoked = True

    qe_identity_ok = False
    if qe_document.verified and qe_document.body is not None:
        qe_identity_ok, qe_detail = evaluate_qe_identity(qe_document.body, qe_report)
        if not qe_identity_ok:
            failures.append(qe_detail)
        if not _is_fresh(qe_document.next_update, now=clock()):
            failures.append("QE identity collateral is stale (past nextUpdate)")
            qe_identity_ok = False

    available = tcb_document.fetched and crl_document.fetched and qe_document.fetched
    return CollateralBundle(
        available=available,
        tcb=tcb_document,
        pckcrl=crl_document,
        qe_identity=qe_document,
        tcb_status=tcb_status,
        tcb_date=tcb_date,
        tcb_acceptable=tcb_acceptable,
        pck_revoked=pck_revoked,
        qe_identity_ok=qe_identity_ok,
        failures=failures,
    )


def _certificate_serial(cert: p256.Certificate) -> int:
    reader = p256._DerReader(cert.tbs_der)
    inner = p256._DerReader(reader.read_sequence())
    if inner.peek_tag() == 0xA0:
        inner.read_raw_tlv()
    return inner.read_integer()
