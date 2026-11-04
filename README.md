# AOP Reference Harness

`aop-reference-harness` is the single authority for the reference runtime of an Agentic Operating Procedure: the runtime loop, the bounded-execution guardrail outside the model context, the scoped credential broker, the escalation dispatch, the approver evidence bundle, and the append-only tamper-evident case record.

| Field | Value | 
|---|---|
| Authority | A working harness: runtime loop, guardrail, credential broker, escalation, evidence record |
| Tier | Runtime |
| Landing wave | 4 |
| Version | 0.2.0 |
| Status | Stable |
| Licence | MIT |

## What this repository owns

- The runtime loop: snapshot, match, authorise, execute, record, emit (NM-STR-13), with fail-closed behaviour on an unmatched variant (NM-STR-9, SEC-5).
- The guardrail: the policy decision point and policy enforcement point that sit outside the model context. The agent proposes; the guardrail disposes (SEC-1, SEC-2).
- The credential broker: short-lived credentials scoped to one action class, issued after approval for high-risk actions, never before (SEC-3, ARC-C1 to ARC-C3).
- The escalation dispatch and the evidence bundle: the approver rules on a case, not on a mystery (SEC-9).
- The case record: append-only, hash-chained, tamper-evident; every decision replayable (SEC-8, SEC-10).
- The harness's own top-level AOP for the fault management domain (`aops/HR-LINE-001.json`), conformant against the schema, per SEC-11: a harness that has not been specified as an AOP is a runtime.
- The Phase 4 end-to-end gate (`gate/end_to_end.py`).

## What this repository does not own

- The normative clauses implemented here. That is `aop-spec`.
- The mining and compilation of the AOPs the harness executes. That is `aop-toolkit`.
- The evaluation of how well the harness runs. That is `aop-evaluation`.

## The agent is the least authoritative part

The scripted reference agent (`aop_harness/agent.py`) proposes the matched variant's steps and nothing else. A model-driven agent replaces that one method; the runtime, guardrail, broker and record do not change. That is the test of the layering (ARC-3), and it is why this repository carries no model, no prompt and no framework.

## Known limits of the reference

Stated so nobody mistakes them for semantics: variant triggers and decision rules evaluate over the case context with a strict allowlist interpreter, so a condition mentioning a context element the snapshot did not carry is an unknown condition and fails closed. Rules are matched per proposed action with optional `applies_to` scoping; a rule without scoping governs every action on the path. The human approver is a policy object behind the dispatch interface; a real deployment substitutes a person and nothing else changes.

## Running

```
python3 gate/end_to_end.py          # the Phase 4 gate, end to end
```

## Documentation

| Document | Scope |
|---|---|
| [The runtime loop](./docs/aop-runtime-loop-harness-scope.md) | Loop stages, matching, the enforcement sequence, and the emission path |
