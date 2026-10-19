"""Data-source adapters.

Each adapter is isolated, validates its own responses, and returns a
:class:`~tracesettle.model.SourceReport` plus (where useful) a typed data object
for the orchestrator. Adapters never decide settlement state.
"""
