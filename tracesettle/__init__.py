"""TRACESETTLE — read-only NEAR Intents settlement investigator.

This package never signs, executes, or holds funds. It only reads public data,
normalizes it into evidence, and reconciles that evidence deterministically.
"""

__version__ = "0.2.0"

DISCLAIMER = (
    "TRACESETTLE is a read-only investigation tool. It cannot recover, reverse, "
    "or move funds, and it never requests private keys or seed phrases."
)
