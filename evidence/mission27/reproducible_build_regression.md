# Mission 27 — reproducible-build regression check

Mission 26 added a reproducible build for the TEE signing guest. This mission
changed no build input, so the fix must be preserved unchanged; the checks below
confirm it still holds. No approved hash was updated to make anything pass.

## The fix, as it stands

`tracesettle/near/tee_signing/guest/signing-module/build.sh` remaps the builder's
`CARGO_HOME` to the fixed prefix the approved artifact was compiled under
(`/home/openhands/.cargo`), so the compiler's embedded absolute dependency paths
do not change the bytes. The prefix is not a preference: it is the cargo-home
prefix of the Mission 25 build whose `sha256` the on-chain TEE run attested.

## Verified this mission

Command: `python3 -m tracesettle guest verify`

```
== guest build identity ==
holds: True
recorded_sha256:   eb705a61554fc9823e9e11a61aa0192d2d9fdf51280379098c1b480c025dd6d0
observed_sha256:   eb705a61554fc9823e9e11a61aa0192d2d9fdf51280379098c1b480c025dd6d0
artifact_present:  True
input_digest:          224f93f7356cb3a4a874c95ed7833fdc0b90f7ebd39d63a39a7676d53aae63f9
recorded_input_digest: 224f93f7356cb3a4a874c95ed7833fdc0b90f7ebd39d63a39a7676d53aae63f9
checks:
  [OK ] build_inputs_match
  [OK ] toolchain_pinned - rust-toolchain.toml pins 1.99.1
  [OK ] artifact_sha256
  [OK ] artifact_size - 186462 bytes
RESULT: PASS
```

* `build_identity.json` is present and its `sha256` and `input_digest` match the
  artifact on disk and the recorded values.
* `tests/test_near_reproducible_build.py`: **11 passed**.
* The CI job `TEE guest digest parity` (`.github/workflows/ci.yml`) is unchanged:
  it runs the guest's own cross-language digest tests and then
  `python3 -m tracesettle guest verify --variant wasm|project`, so a rebuild that
  drifts from the approved hash fails the build.

## What was not touched

* No canonical prefix change (`TRACESETTLE_BUILD_CARGO_HOME` default unchanged).
* No approved project/WASM hash updated.
* No change to the TEE measurement or artifact binding.

## Parity across environments

The remap is the mechanism that makes the bytes independent of the builder's
cargo home; the CI job reproduces the artifact under the runner's own home and
compares it to the recorded hash. This mission added no build input, so parity is
unchanged; the local `guest verify` above is the positive control.

---

# Mission 28 addendum — parity re-verified independently (2026-11-08)

The Mission 26 fix is preserved and was re-checked from the shipped package
without changing any input:

```
$ sha256sum tracesettle/near/tee_signing/guest/signing-module/dist/tracesettle-signing-module-wasm.wasm
eb705a61554fc9823e9e11a61aa0192d2d9fdf51280379098c1b480c025dd6d0
$ stat -c%s …-wasm.wasm
186462
$ python3 -m tracesettle guest verify
  [OK ] build_inputs_match - inputs 224f93f7356cb3a4… vs recorded 224f93f7356cb3a4…
  [OK ] toolchain_pinned - rust-toolchain.toml pins 1.99.1
  [OK ] artifact_sha256 - observed eb705a61554fc982… vs recorded eb705a61554fc982…
  [OK ] artifact_size - 186462 bytes
RESULT: PASS
```

The path-remap fix is present in `build.sh` and holds in the committed bytes:
`strings` over the artifact finds the canonical prefix `…/home/openhands/.cargo`
**15 times** and the string `home/runner` **0 times**, so no builder path leaked
into the approved artifact. The project variant is also unchanged
(`7ff8fbcb6748159729f5c6b4ff5659ba99d3c5c906ecc9d1bde7478e37f57691`).

The approved-build hash `eb705a61554fc982…` is the same value the Mission 25
on-chain run attested, so the attestation binding remains valid; the canonical
prefix was **not** changed.
