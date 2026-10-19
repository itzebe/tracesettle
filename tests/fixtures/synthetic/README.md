# Synthetic fixtures

These files are **hand-authored for testing only**. They are **not** real
transactions and must never be presented as live evidence.

| File | Purpose |
| --- | --- |
| `oneclick_status_REFUNDED.json` | A 1Click status record reporting `REFUNDED` with a positive `refundedAmount`, for refund scenarios. |
| `oneclick_status_FAILED.json` | A 1Click status record reporting `FAILED` with `refundedAmount: "0"`, for the "zero refund is not proof of no refund" scenario. |
| `evm_receipt_refund_verified.json` | An EVM receipt whose logs contain a matching ERC-20 `Transfer` to the refund address, used to test refund *verification*. |

Every file carries a `_provenance` field marking it as synthetic. The test suite
loads real captures from `evidence/raw/` and these synthetic files separately, so
provenance is never mixed.
