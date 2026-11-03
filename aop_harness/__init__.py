"""aop_harness: the reference domain agent harness.

Implements the runtime loop (snapshot, match, authorise, execute, record,
emit), the bounded-execution guardrail outside the model context, the scoped
credential broker, the escalation dispatch, the approver evidence bundle, and
the append-only tamper-evident case record. Standard library only.
"""

__version__ = "0.1.0"
