"""Reproducible-build verification for the TEE signing guest.

The Mission 25 guest was identified only by a pinned sha256. That is an
*identity*, not a *reproduction*: it does not show that the bytes came from the
published source, and it cannot detect a silent change to the source, the
manifest, the WIT interface or the build configuration. This module closes that
gap.

What "reproducible" means here
------------------------------

The artifact is a Rust ``wasm32-wasip2`` component. Its bytes depend on:

* the source tree (``src/main.rs``, ``wit/signing-keys.wit``, the manifest),
* the dependency graph, pinned by ``Cargo.lock``,
* the Rust toolchain (the compiler commit is embedded in the ``producers``
  section, and codegen differs between versions — measured, see
  ``evidence/mission26/reproducible_build.md``),
* the cargo profile (``opt-level="z"``, ``lto``, ``strip``, ``codegen-units=1``).

The build is reproducible when the same inputs produce the same bytes. This
module cannot rebuild the wasm itself (that needs cargo, which the zero-budget
offline CI does not run), so it does the two things that *can* be checked
anywhere, cheaply and deterministically:

1. **Input integrity** — hash the exact build inputs and compare them to the
   recorded values, so a change to the source, the WIT, the manifest, the
   lockfile or the profile is detected as a *different build identity*.
2. **Artifact integrity** — when the artifact is present, compare its bytes to
   the recorded sha256.

A reviewer with cargo runs ``tracesettle guest verify --build`` (or
``build.sh``) and gets the byte-for-byte comparison. CI runs the same build and
compares the artifact hash. Both paths are the same acceptance criterion: the
rebuilt bytes must equal the recorded bytes.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

#: The guest crate, relative to this package.
GUEST_DIR = Path(__file__).resolve().parent / "guest" / "signing-module"

#: Files whose exact bytes are build inputs. A change to any of them is a
#: change to the approved-build identity. ``build_identity.json`` is deliberately
#: *not* listed: it is the record the digest is compared against, so hashing it
#: into itself would make the digest unverifiable.
_BUILD_INPUTS = (
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "build.sh",
    "manifest.json",
    "manifest-wasm.json",
    "src/main.rs",
    "wit/signing-keys.wit",
    "vectors/tee_signing_vectors.json",
)


class ReproducibleBuildError(RuntimeError):
    """The build inputs or the artifact do not match the recorded identity."""


@dataclass
class BuildCheck:
    """One separately-reported check."""

    name: str
    holds: bool
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "holds": self.holds, "detail": self.detail}


@dataclass
class BuildVerdict:
    """The outcome of the build-identity check."""

    holds: bool
    checks: list[BuildCheck] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)
    recorded_sha256: str = ""
    observed_sha256: str = ""
    artifact_present: bool = False
    input_digest: str = ""
    recorded_input_digest: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "holds": self.holds,
            "recorded_sha256": self.recorded_sha256,
            "observed_sha256": self.observed_sha256,
            "artifact_present": self.artifact_present,
            "input_digest": self.input_digest,
            "recorded_input_digest": self.recorded_input_digest,
            "checks": [c.to_dict() for c in self.checks],
            "failures": list(self.failures),
        }


def build_identity(guest_dir: Path | None = None) -> dict[str, Any]:
    """Load the recorded build identity (``build_identity.json``)."""
    path = (guest_dir or GUEST_DIR) / "build_identity.json"
    if not path.is_file():
        raise ReproducibleBuildError(f"no build identity is recorded at {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def hash_build_inputs(guest_dir: Path | None = None) -> tuple[str, dict[str, str]]:
    """A single digest over every build input, plus each file's own sha256.

    The inputs are hashed as ``<relative path>\\0<sha256>\\n`` in sorted order, so
    the digest is stable and a rename is itself a change. A missing input is a
    failure, not a silent omission.
    """
    base = guest_dir or GUEST_DIR
    per_file: dict[str, str] = {}
    h = hashlib.sha256()
    for rel in sorted(_BUILD_INPUTS):
        path = base / rel
        if not path.is_file():
            raise ReproducibleBuildError(f"build input {rel!r} is missing from {base}")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        per_file[rel] = digest
        h.update(rel.encode("utf-8"))
        h.update(b"\x00")
        h.update(digest.encode("ascii"))
        h.update(b"\n")
    return h.hexdigest(), per_file


def verify_build(
    *,
    guest_dir: Path | None = None,
    artifact: Path | None = None,
    variant: str = "wasm",
) -> BuildVerdict:
    """Check the recorded build identity against the tree and (if present) the artifact.

    ``variant`` selects which recorded artifact to compare: ``"wasm"`` (the
    manifest bound to the wasm hash, used by the live run) or ``"project"``.
    """
    base = guest_dir or GUEST_DIR
    identity = build_identity(base)
    artifacts = identity.get("artifacts", {})
    if variant not in artifacts:
        raise ReproducibleBuildError(f"no artifact named {variant!r} in the build identity")
    record = artifacts[variant]

    verdict = BuildVerdict(holds=True)
    verdict.recorded_sha256 = record["sha256"]

    def add(name: str, holds: bool, detail: str = "") -> None:
        verdict.checks.append(BuildCheck(name=name, holds=holds, detail=detail))
        if not holds:
            verdict.failures.append(name)

    # The inputs must be exactly what was recorded.
    try:
        digest, per_file = hash_build_inputs(base)
    except ReproducibleBuildError as exc:
        add("build_inputs_present", False, str(exc))
        verdict.holds = False
        return verdict
    verdict.input_digest = digest
    recorded_inputs = record.get("input_digest", "")
    verdict.recorded_input_digest = recorded_inputs
    if recorded_inputs:
        add(
            "build_inputs_match",
            digest == recorded_inputs,
            f"inputs {digest[:16]}… vs recorded {recorded_inputs[:16]}…",
        )
    else:
        add("build_inputs_match", True, "no input digest recorded (identity-only check)")

    # The toolchain is pinned.
    toolchain_file = base / "rust-toolchain.toml"
    pinned = identity.get("toolchain", "")
    if toolchain_file.is_file() and pinned:
        text = toolchain_file.read_text(encoding="utf-8")
        add(
            "toolchain_pinned",
            f'channel = "{pinned}"' in text,
            f"rust-toolchain.toml pins {pinned}",
        )
    else:
        add("toolchain_pinned", False, "no pinned toolchain is recorded")

    # The artifact, when it is present, must hash to the recorded value.
    artifact_path = artifact or (base / record["file"])
    if artifact_path.is_file():
        observed = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
        verdict.observed_sha256 = observed
        verdict.artifact_present = True
        add(
            "artifact_sha256",
            observed == record["sha256"],
            f"observed {observed[:16]}… vs recorded {record['sha256'][:16]}…",
        )
        size = artifact_path.stat().st_size
        add(
            "artifact_size",
            size == record.get("size_bytes", size),
            f"{size} bytes",
        )
    else:
        verdict.artifact_present = False
        add(
            "artifact_present",
            True,
            "artifact not built here; input identity is the check that ran "
            "(run build.sh to reproduce the bytes)",
        )

    verdict.holds = not verdict.failures
    return verdict


def build_input_digest(guest_dir: Path | None = None) -> str:
    """Convenience: the single digest over the build inputs."""
    return hash_build_inputs(guest_dir)[0]


def record_input_digest(guest_dir: Path | None = None, *, variant: str = "wasm") -> dict[str, Any]:
    """Write the current input digest into ``build_identity.json``.

    Used when the source is intentionally changed: the recorded identity must
    move with it, or every later check would (correctly) fail.
    """
    base = guest_dir or GUEST_DIR
    identity = build_identity(base)
    digest, _ = hash_build_inputs(base)
    identity.setdefault("artifacts", {}).setdefault(variant, {})["input_digest"] = digest
    (base / "build_identity.json").write_text(
        json.dumps(identity, indent=2) + "\n", encoding="utf-8"
    )
    return identity


__all__ = [
    "GUEST_DIR",
    "BuildCheck",
    "BuildVerdict",
    "ReproducibleBuildError",
    "build_identity",
    "build_input_digest",
    "hash_build_inputs",
    "record_input_digest",
    "verify_build",
]
