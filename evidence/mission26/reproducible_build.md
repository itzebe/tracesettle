# Mission 26 — Reproducible build

Recorded 2026-11-08. Everything below was measured on this machine; nothing is
asserted without a command and its output.

## The claim

The TEE signing guest is identified by a pinned sha256. Mission 26 turns that
*identity* into a *reproduction*: the same source, the same dependency graph, the
same build configuration and the same compiler must produce the same bytes.

## The inputs

The guest crate is `tracesettle/near/tee_signing/guest/signing-module/`. Its bytes
depend on:

| Input | Why it matters |
| --- | --- |
| `src/main.rs`, `wit/signing-keys.wit`, `manifest*.json` | the source and the interface |
| `Cargo.lock` | the exact dependency graph |
| `rust-toolchain.toml` | the compiler release |
| `build.sh` | the profile and the two feature sets |
| `vectors/tee_signing_vectors.json` | the cross-language digest vectors |

`build_identity.json` records the sha256 of each artifact plus a single digest
over every input above (`input_digest`). It deliberately does **not** hash itself.

## The toolchain pin

`rust-toolchain.toml` pins `channel = "1.99.1"`. This is not cosmetic. The
compiler commit is embedded in the wasm `producers` custom section, and codegen
differs between releases, so a different rustc yields different bytes. Measured:

```
$ rustup toolchain list
stable-x86_64-unknown-linux-gnu (active, default)
1.95.0-x86_64-unknown-linux-gnu
1.99.1-x86_64-unknown-linux-gnu

$ rustc --version
rustc 1.99.1 (58cf8f9c3 2026-10-13)
```

## The reproduction

`bash build.sh` builds both feature variants and runs the guest's own tests.

```
── project (--features project) ──
Built:  dist/tracesettle-signing-module.wasm
Size:   182 KB
SHA256: 7ff8fbcb6748159729f5c6b4ff5659ba99d3c5c906ecc9d1bde7478e37f57691

── wasm (--features wasm) ──
Built:  dist/tracesettle-signing-module-wasm.wasm
Size:   182 KB
SHA256: eb705a61554fc9823e9e11a61aa0192d2d9fdf51280379098c1b480c025dd6d0

── cargo test (digest parity with tracesettle) ──
test result: ok. 4 passed; 0 failed
```

`eb705a61554fc982…` is the approved-build identity the Mission 25 live run used
(`build_identity.json → artifacts.wasm.sha256`).

## From scratch, not from cache

A cached artifact proves nothing. `cargo clean` was run, the approved bytes were
copied aside, and the whole build was repeated with no cache:

```
$ cargo clean
$ bash build.sh          # 16.97 s of real compilation (curve25519-dalek, ed25519-dalek, …)
...
SHA256: eb705a61554fc9823e9e11a61aa0192d2d9fdf51280379098c1b480c025dd6d0

$ cmp /tmp/approved_copy.wasm dist/tracesettle-signing-module-wasm.wasm
$ sha256sum /tmp/approved_copy.wasm dist/tracesettle-signing-module-wasm.wasm
eb705a61554fc9823e9e11a61aa0192d2d9fdf51280379098c1b480c025dd6d0  /tmp/approved_copy.wasm
eb705a61554fc9823e9e11a61aa0192d2d9fdf51280379098c1b480c025dd6d0  dist/tracesettle-signing-module-wasm.wasm
BYTE-IDENTICAL: a clean rebuild reproduces the approved artifact
```

The full build log is `evidence/mission26/guest_clean_rebuild.log`.

### Independent re-check (2026-11-06)

Re-run in this session with the same pinned toolchain, after the artifacts were
copied aside and `cargo clean` removed 1015 files (249.9 MiB):

```
$ cargo clean
Removed 1015 files, 249.9MiB total
$ bash build.sh
Built:  dist/tracesettle-signing-module.wasm       SHA256: 7ff8fbcb67481597…
Built:  dist/tracesettle-signing-module-wasm.wasm  SHA256: eb705a61554fc982…

$ cmp /tmp/before-wasm.wasm    dist/tracesettle-signing-module-wasm.wasm && echo "wasm variant: BYTE-IDENTICAL"
$ cmp /tmp/before-project.wasm dist/tracesettle-signing-module.wasm      && echo "project variant: BYTE-IDENTICAL"
wasm variant: BYTE-IDENTICAL
project variant: BYTE-IDENTICAL
```

Both variants reproduce byte for byte from a cold cache. `guest verify` passes
for `--variant wasm` and `--variant project`.

## What the reviewer can check without cargo

`python3 -m tracesettle guest verify` checks the inputs and (when present) the
artifact, from the shipped package:

```
$ python3 -m tracesettle guest verify
checks:
  [OK ] build_inputs_match - inputs 224f93f7356cb3a4… vs recorded 224f93f7356cb3a4…
  [OK ] toolchain_pinned - rust-toolchain.toml pins 1.99.1
  [OK ] artifact_sha256 - observed eb705a61554fc982… vs recorded eb705a61554fc982…
  [OK ] artifact_size - 186462 bytes
RESULT: PASS
```

## Machine independence — a defect CI caught

The first CI run of this branch **failed**, and the failure was real: the
committed artifact did not match a clean rebuild on the runner.

```
observed_sha256: dd47be883742a7c1fad178b615b55aeeaadcb71cf63f49d140cbb474e9b21875
recorded_sha256: eb705a61554fc9823e9e11a61aa0192d2d9fdf51280379098c1b480c025dd6d0
artifact_size:   186414 bytes (recorded 186462)
```

The cause was not the toolchain (the runner installed the pinned `1.99.1`,
`rustc 1.99.1 (58cf8f9c3 2026-10-13)`). It was that **rustc embeds the absolute
path of every dependency source it reads** — cargo's registry cache — into the
wasm. The committed artifact carried `/home/openhands/.cargo/registry/…` fifteen
times; the runner built under `/home/runner/.cargo/…`, so the same source, the
same lockfile and the same compiler produced different bytes. The artifact was
reproducible only on a machine whose home happened to be `/home/openhands`.

The fix is in `build.sh`: remap the builder's cargo home to the fixed prefix the
approved artifact was built under, so the bytes identify the *inputs*, not the
machine.

```
CANONICAL_CARGO_HOME="${TRACESETTLE_BUILD_CARGO_HOME:-/home/openhands/.cargo}"
… --remap-path-prefix="$ACTUAL_CARGO_HOME=$CANONICAL_CARGO_HOME"
```

Measured, building from a *different* cargo home and a *different* crate
directory:

```
$ CARGO_HOME=/tmp/rebuildcargo3 bash build.sh     # in /tmp/rebuild3/signing-module
Path remap: /tmp/rebuildcargo3 -> /home/openhands/.cargo
SHA256: 7ff8fbcb6748159729f5c6b4ff5659ba99d3c5c906ecc9d1bde7478e37f57691   (project)
SHA256: eb705a61554fc9823e9e11a61aa0192d2d9fdf51280379098c1b480c025dd6d0   (wasm)
```

Both variants now reproduce the approved hashes from an arbitrary directory. The
canonical prefix is `…/home/openhands/.cargo` — not because that is "correct", but
because that is the prefix baked into the artifact the Mission 25 on-chain run
attested (`eb705a61…`); changing it would change the hash and break the on-chain
binding. Every other machine remaps *to* it. Two regression tests guard this
(`test_the_build_remaps_the_cargo_home_so_paths_do_not_leak_in`,
`test_the_approved_artifact_embeds_only_the_canonical_cargo_home`).

Because `build.sh` is itself a hashed build input, the recorded `input_digest`
was updated to `224f93f7356cb3a4…`; the artifact hashes are unchanged.

## What CI does

The `TEE guest digest parity` job installs toolchain `1.99.1`, runs
`bash build.sh`, and then runs `guest verify` for both variants — so a change to
any input, the profile, or the compiler fails the build with the two hashes
printed.

## Honest limits

* Reproducibility is established for **this** toolchain. A different rustc is a
  different build identity by design; the pin is what makes the check meaningful.
* `cargo`/`rustup` are needed to *rebuild*; the verifier itself needs only the
  Python standard library, so an auditor without Rust can still check the recorded
  identity and, when the bytes are shipped, the artifact hash.
* The guest was never published at a permanent URL (the Mission 25 host was
  temporary and is now unreachable, HTTP 502). The approved-build identity rests
  on the reproducible rebuild and the sha256 pin, not on that URL.
