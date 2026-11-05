# Changelog

All notable changes to this repository are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning is semantic: the major version changes when the runtime loop sequence or the enforcement semantics change, the minor version when substantive runtime content is added, and the patch version for corrections that do not change meaning.

## [Unreleased]

## [v0.5.0] - 2026-11-05

### Added (Wave H3: CR-021/022/024/025/026)

- Workload identity per run with cross-workload credential refusal (SEC-16); the component matrix stamped on every case-record entry (NM-VER-8).
- The incident lifecycle: declare-respond-recover with the integrity check and owner-gated resumption (CR-025).
- Erasure-compatible evidence: payload externalisation to a side store, shredding with an appended tombstone, chain preserved, replay claims narrowed (NM-ASR-7).
- In-flight migration markers (RA-23).


## [v0.4.0] - 2026-11-05

### Added (Wave H2)

- The approval object in the dispatch: bundles bind the action digest and expiry; rulings carry the four outcomes; non-response routes to the fallback role and never approves (RA-15, RA-16).
- Canary bundles and oversight metrics: approval rate, time-to-approve, canary detection with the failing-approver alert (RA-19).
- Parameter validation against the AOP's declared schemas at execution time (RA-21).
- The revocation hook: a run consults the bound version's revocation state and a revoked version holds (NM-VER-6).


## [v0.3.0] - 2026-11-05

### Added (Wave H1: CR-011, CR-012, CR-009-3)

- Action digests (RA-5): canonical digest of name, target and payload; the runtime binds decisions and credentials to the digest; duplicate delivery is answered from the record (RA-10).
- Budget verdicts beside the authority check (NM-CRD-4) with per-case usage counters.
- Irreversibility verdicts (NM-AUT-8): an irreversible action's autonomous verdict is raised to approval-required.
- The replay module (RP-1 to RP-7): R1 record verification and R2 decision-trace reconstruction from the record alone, with third-party verification; R3 deliberately unimplemented, a record is not an authorization.


## [0.2.0] - 2026-11-05

### Added (CR-009 block 1)

- The decision point sees only system-attested and derived facts (NM-STR-16): the trusted view is built from the AOP's declared context elements, keyed by their runtime keys.
- Hold semantics (SEC-14): enforcement failure holds the run with a recorded hold; it never proceeds.
- Emergency stop (SEC-15): a named role halts the domain; resumption requires the accountable owner; both are recorded.


## [0.1.0] - 2026-11-04

### Reference runtime

- Published the runtime loop: snapshot, match, authorise, execute, record, emit, with fail-closed matching and the enforcement sequence outside the model context.
- Published the guardrail: prohibited set, permitted set, decision-rule matching with applies_to scoping, default authority class, and fail-closed behaviour on unknown conditions and unmatched variants.
- Published the credential broker: one-shot, action-class-scoped, short-lived credentials, issued after approval for high-risk classes, with a full issuance log for the case record.
- Published the escalation dispatch and evidence bundles: the approver sees the proposed action, the triggering rule, its observed provenance, the baseline comparison and the case context.
- Published the append-only, hash-chained, tamper-evident case record with chain verification.
- Published the harness's own top-level AOP for the fault management domain, conformant against the aop-spec schema (SEC-11).
- Published the scripted reference agent: the least authoritative, most replaceable part of the estate.
- Published the Phase 4 end-to-end gate and passed it: one procedure compiles, publishes, resolves with an intact provenance chain, and executes 40 cases under the guardrail with complete, chain-verified case records.

[Unreleased]: https://github.com/agentic-operating-procedure/aop-reference-harness/compare/v0.5.0...HEAD
[v0.5.0]: https://github.com/agentic-operating-procedure/aop-reference-harness/compare/v0.4.0...v0.5.0
[v0.4.0]: https://github.com/agentic-operating-procedure/aop-reference-harness/compare/v0.3.0...v0.4.0
[v0.3.0]: https://github.com/agentic-operating-procedure/aop-reference-harness/compare/v0.2.0...v0.3.0
[v0.2.0]: https://github.com/agentic-operating-procedure/aop-reference-harness/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/agentic-operating-procedure/aop-reference-harness/releases/tag/v0.1.0
