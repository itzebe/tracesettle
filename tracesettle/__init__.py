"""TRACESETTLE — security infrastructure for autonomous payments.

Two capabilities, one deterministic core:

* **Pre-execution authorization** (:mod:`tracesettle.guard`,
  :mod:`tracesettle.near`): evaluate the *actual* transaction parameters before
  execution and refuse anything outside policy, so an unauthorized payment never
  reaches a signer that consults this boundary.
* **Settlement investigation** (:mod:`tracesettle.investigation`,
  :mod:`tracesettle.reconcile`): read public chain data, normalize it into
  evidence, and reconcile that evidence deterministically so a provider's claim
  is never mistaken for proof.

Neither capability holds funds. The public investigation interface is read-only;
signing, where offered, happens only through an explicit enforcement boundary the
operator configures, and the reference executor is simulated.
"""

__version__ = "0.2.0"

DISCLAIMER = (
    "TRACESETTLE never requests private keys or seed phrases, and it cannot "
    "recover, reverse, or move funds. Any signing happens only through an "
    "explicit enforcement boundary the operator configures; the reference "
    "executor is simulated and broadcasts nothing."
)
