"""The reproducible-build identity of the TEE signing guest.

These tests are deliberately about *inputs*, because that is the part that can be
checked without cargo. They assert that:

* the recorded identity is present and internally consistent;
* a change to any build input changes the digest, so a silent source edit cannot
  pass as the approved build;
* a change to the artifact changes its hash (checked when the artifact exists);
* the toolchain is pinned, because the bytes are toolchain-sensitive.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from tracesettle.near.tee_signing.build_verify import (
    GUEST_DIR,
    ReproducibleBuildError,
    build_identity,
    hash_build_inputs,
    verify_build,
)

REPO = Path(__file__).resolve().parents[1]


def test_the_recorded_build_identity_is_present_and_consistent():
    identity = build_identity()
    assert identity["toolchain"] == "1.99.1"
    assert identity["target"] == "wasm32-wasip2"
    wasm = identity["artifacts"]["wasm"]
    assert wasm["sha256"] == (
        "eb705a61554fc9823e9e11a61aa0192d2d9fdf51280379098c1b480c025dd6d0"
    )
    assert wasm["used_by_live_run"] is True


def test_the_tree_matches_the_recorded_input_identity():
    verdict = verify_build()
    assert verdict.holds, verdict.failures
    assert verdict.input_digest == verdict.recorded_input_digest
    assert verdict.recorded_sha256 == verdict.observed_sha256


def test_the_toolchain_is_pinned_in_the_crate():
    text = (GUEST_DIR / "rust-toolchain.toml").read_text(encoding="utf-8")
    assert 'channel = "1.99.1"' in text
    assert "wasm32-wasip2" in text


def test_changing_a_build_input_changes_the_digest(tmp_path):
    copy = tmp_path / "signing-module"
    shutil.copytree(GUEST_DIR, copy)
    before, _ = hash_build_inputs(copy)
    source = copy / "src/main.rs"
    source.write_text(source.read_text(encoding="utf-8") + "\n// tampered\n", encoding="utf-8")
    after, _ = hash_build_inputs(copy)
    assert before != after


def test_changing_the_lockfile_changes_the_digest(tmp_path):
    copy = tmp_path / "signing-module"
    shutil.copytree(GUEST_DIR, copy)
    before, _ = hash_build_inputs(copy)
    lock = copy / "Cargo.lock"
    lock.write_text(lock.read_text(encoding="utf-8") + "\n# tampered\n", encoding="utf-8")
    after, _ = hash_build_inputs(copy)
    assert before != after


def test_a_modified_tree_fails_verification(tmp_path):
    copy = tmp_path / "signing-module"
    shutil.copytree(GUEST_DIR, copy)
    source = copy / "src/main.rs"
    source.write_text(source.read_text(encoding="utf-8") + "\n// tampered\n", encoding="utf-8")
    verdict = verify_build(guest_dir=copy)
    assert not verdict.holds
    assert "build_inputs_match" in verdict.failures


def test_a_missing_input_is_an_error_not_a_silent_pass(tmp_path):
    copy = tmp_path / "signing-module"
    shutil.copytree(GUEST_DIR, copy)
    (copy / "wit/signing-keys.wit").unlink()
    with pytest.raises(ReproducibleBuildError):
        hash_build_inputs(copy)


def test_a_tampered_artifact_fails_verification(tmp_path):
    artifact = tmp_path / "artifact.wasm"
    artifact.write_bytes(b"not the approved build")
    verdict = verify_build(artifact=artifact)
    assert not verdict.holds
    assert "artifact_sha256" in verdict.failures


def test_the_artifact_is_present_in_this_checkout():
    # The pinned artifact is committed in the repository, so the byte comparison
    # runs here rather than being skipped.
    artifact = GUEST_DIR / "dist/tracesettle-signing-module-wasm.wasm"
    assert artifact.is_file(), "the pinned guest artifact is missing from the repo"
    verdict = verify_build()
    assert verdict.artifact_present
    assert verdict.observed_sha256 == verdict.recorded_sha256


def test_the_build_remaps_the_cargo_home_so_paths_do_not_leak_in():
    """The compiler embeds the dependency-source path; it must be canonical.

    A build under a different ``CARGO_HOME`` otherwise produces different bytes
    (measured: the committed artifact embedded ``/home/openhands/.cargo``), so
    the artifact would identify the *machine*, not the inputs. ``build.sh`` must
    remap the builder's cargo home to the fixed prefix baked into the approved
    artifact.
    """
    text = (GUEST_DIR / "build.sh").read_text(encoding="utf-8")
    assert "--remap-path-prefix" in text
    assert "TRACESETTLE_BUILD_CARGO_HOME" in text
    # The canonical prefix must be the one the approved artifact was built under,
    # or the remap would change the bytes and break the pinned hash.
    assert "/home/openhands/.cargo" in text


def test_the_approved_artifact_embeds_only_the_canonical_cargo_home():
    """The artifact must carry exactly one cargo-home prefix, and it is canonical.

    The compiler embeds the dependency-source path, so a build under a different
    ``CARGO_HOME`` produces different bytes. ``build.sh`` remaps the builder's
    home to the fixed prefix baked into the approved artifact, so the bytes are
    reproducible from any machine while the pinned hash is unchanged.

    That prefix is ``/home/openhands/.cargo`` because it is what the Mission 25
    on-chain TEE run attested (``eb705a61…``); changing it would change the hash
    and break the on-chain binding. It is therefore a build *constant*, not a
    leaked machine path — every other machine remaps to it. The toolchain's own
    ``/rustc/<commit>/`` paths are identical for every builder of the release.
    """
    import re

    artifact = GUEST_DIR / "dist/tracesettle-signing-module-wasm.wasm"
    blob = artifact.read_bytes()
    cargo_homes = set(re.findall(rb"/[^ \x00]*?/\.cargo", blob))
    assert cargo_homes == {b"/home/openhands/.cargo"}, cargo_homes
    # No *other* machine path may appear: a workspace, tmp or user dir would make
    # the artifact depend on where it was built.
    for prefix in (b"/workspace/", b"/tmp/", b"/Users/", b"/root/"):
        assert prefix not in blob, f"the artifact embeds a machine path {prefix!r}"
