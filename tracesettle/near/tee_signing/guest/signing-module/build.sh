#!/bin/bash
# Builds the TraceSettle TEE signing module for OutLayer.
#
# The module is a WASI Preview 2 command component that composes the NEAR
# transaction digest and asks the OutLayer enclave to sign it. OutLayer refuses
# a WASI P1 module that declares signing keys, so the target is wasm32-wasip2.
#
# Two builds, one per manifest:
#   dist/tracesettle-signing-module.wasm        key bind "project" (a project version)
#   dist/tracesettle-signing-module-wasm.wasm   key bind "wasm"    (a direct run of the URL)
#
# The sha256 of a build is the approved-build identity an operator pins.
set -e
cd "$(dirname "$0")"

TARGET=wasm32-wasip2
BUILT="target/$TARGET/release/tracesettle-signing-module.wasm"

# The WIT here is a COPY of OutLayer's `sdk/outlayer/wit/deps/signing-keys.wit`.
# A drifted copy compiles against an interface the host no longer provides, and
# fails at runtime as a missing import — so a drift is reported, not silently
# fixed. Point OUTLAYER_WIT at the worker copy to run the check.
if [ -n "${OUTLAYER_WIT:-}" ] && [ -f "$OUTLAYER_WIT" ]; then
    if ! diff -q "$OUTLAYER_WIT" wit/signing-keys.wit >/dev/null; then
        echo "ERROR: wit/signing-keys.wit has drifted from $OUTLAYER_WIT" >&2
        diff "$OUTLAYER_WIT" wit/signing-keys.wit || true
        exit 1
    fi
    echo "WIT: wit/signing-keys.wit matches $OUTLAYER_WIT"
fi

rustup target add "$TARGET" 2>/dev/null || true
mkdir -p dist

# The compiler embeds the absolute path of every dependency source it reads
# (cargo's registry cache) into the artifact, so a build under a different
# CARGO_HOME produces different bytes even with identical source, lockfile and
# compiler. Remap the builder's cargo home to the fixed prefix baked into the
# approved artifact, so the bytes identify the *inputs*, not the machine that
# built them.
#
# The prefix below is not a preference: it is the cargo-home prefix the approved
# artifact `eb705a61554fc982…` was compiled under (the Mission 25 build
# environment), and that hash is what the on-chain TEE run attested. The crate's
# own directory is not embedded, so CARGO_HOME is the only machine-specific
# input — measured with `--remap-path-prefix` from two different homes.
CANONICAL_CARGO_HOME="${TRACESETTLE_BUILD_CARGO_HOME:-/home/openhands/.cargo}"
if [ -n "${CARGO_HOME:-}" ]; then
    ACTUAL_CARGO_HOME="$CARGO_HOME"
elif [ -n "${HOME:-}" ]; then
    ACTUAL_CARGO_HOME="$HOME/.cargo"
else
    ACTUAL_CARGO_HOME=""
fi
if [ -n "$ACTUAL_CARGO_HOME" ] && [ "$ACTUAL_CARGO_HOME" != "$CANONICAL_CARGO_HOME" ]; then
    REMAP="--remap-path-prefix=$ACTUAL_CARGO_HOME=$CANONICAL_CARGO_HOME"
    export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }$REMAP"
    echo "Path remap: $ACTUAL_CARGO_HOME -> $CANONICAL_CARGO_HOME"
fi

build() {
    local variant=$1 features=$2 out="dist/tracesettle-signing-module$3.wasm"
    echo ""
    echo "── $variant (--features $features) ──"
    cargo build --release --target "$TARGET" --no-default-features --features "$features"
    cp "$BUILT" "$out"

    # The manifest must be in the artefact: without it the worker hands out no
    # keys and every call is refused.
    if ! grep -qa 'outlayer.manifest' "$out"; then
        echo "ERROR: the outlayer.manifest custom section is missing from $out" >&2
        exit 1
    fi
    if ! grep -qa 'outlayer:signing-keys' "$out"; then
        echo "ERROR: $out does not import outlayer:signing-keys" >&2
        exit 1
    fi
    echo "Built:  $out"
    echo "Size:   $(( $(stat -c%s "$out" 2>/dev/null || stat -f%z "$out") / 1024 )) KB"
    echo "SHA256: $(sha256sum "$out" 2>/dev/null | cut -d' ' -f1 || shasum -a 256 "$out" | cut -d' ' -f1)"
}

build project project ""
build wasm    wasm    "-wasm"

# The digest rule must still agree with the product's own serializer.
echo ""
echo "── cargo test (digest parity with tracesettle) ──"
cargo test --release --quiet
