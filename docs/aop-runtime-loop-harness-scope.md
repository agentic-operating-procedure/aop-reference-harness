# AOP Runtime Loop (Harness Scope)

Informative. This document describes the reference implementation of the runtime loop against the normative sequence in `aop-spec` (NM-STR-13) and the architecture in `aop-architecture`. The modules: `guardrail.py` (decision and enforcement), `broker.py` (credentials), `evidence.py` (bundles and dispatch), `caserecord.py` (the record), `runtime.py` (the loop), `agent.py` (the proposer).

## 1. The loop, stage by stage

| Stage | Implementation | Normative anchor |
|---|---|---|
| Snapshot | The case context is copied and referenced by a `cg://case/` URI; the snapshot is immutable for the run | NM-CTX-2 |
| Match | `Guardrail.match_variant`: machine-evaluable variant triggers are tested in declared order against the context; a prose trigger is the declared residual fallback; no match fails closed | NM-STR-8, NM-STR-9, SEC-5 |
| Authorise | `Guardrail.authorise`: prohibited set first, permitted set second, then the first matching decision rule on the matched variant, then the default authority class, then fail closed | NM-AUT-2, NM-AUT-3, NM-CON-1, SEC-5, SEC-6 |
| Execute | The harness executes the approved action under a one-shot scoped credential from the broker; a refused or expired credential fails closed | SEC-3, ARC-C1 to ARC-C3 |
| Record | Every disposition appends to the hash-chained case record: inputs, context snapshot, rule, provenance, decision, approver, outcome | NM-ASR-1, SEC-6, SEC-8 |
| Emit | The record store is the emission: execution evidence becomes substrate observation | ARC-P5 |

## 2. The enforcement sequence, per proposed action

```
proposed action
   |
   v
in prohibited set? ---------------- yes --> PROHIBIT, record, continue
   | no
in permitted set? ---------------- no -----> ESCALATE (outside permitted set, NM-CON-1)
   | yes
first matching decision rule?
   | rule says autonomous -------> EXECUTE with scoped credential
   | rule says approval-required -> evidence bundle -> dispatch -> approver rules
   |                                    approved: EXECUTE with scoped credential
   |                                    rejected: record, stop the run
   | rule says prohibited -------> PROHIBIT, record, continue
   | no rule matched
   v
default authority class ---------- prohibited -> ESCALATE (NM-AUT-3)
   | autonomous / approval-required
   v
as above
```

There is no path that proceeds without a record (SEC-6), and no path where the agent's proposal alone causes execution.

## 3. Rule scoping and unknown conditions

- A decision rule may carry `applies_to`: an explicit action scope. A scoped rule governs only the actions it names; for other actions the match continues down the rule list. Without scoping, a rule governs every action on the path, which is why the manifest scopes condition-family rules such as thresholds to the action they decide.
- A condition that reads a context element the snapshot did not carry is an unknown condition (SEC-5): the rule does not match, the search continues, and if nothing matches the default class applies or the run fails closed. Unknown is never false.

## 4. The case record

`CaseRecordStore` appends JSONL entries as a SHA-256 hash chain: each entry carries the hash of its predecessor and its own content hash. `verify_chain` recomputes the chain over the whole file; any edit, deletion or reordering breaks it. The store appends only; there is no update or delete operation to call.

## 5. The emission and the loop back

The case records this harness writes are cases in the substrate's shape family: the runtime projection of inputs, context snapshot, rule, provenance, decision, approver and outcome. They join the observation corpus for the next compile (ARC-P5, ARC-P6), and they never mutate the AOP version that produced them (NM-ASR-4).
