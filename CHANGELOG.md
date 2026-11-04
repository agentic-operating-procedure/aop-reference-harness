# Changelog

All notable changes to this repository are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning is semantic: the major version changes when the runtime loop sequence or the enforcement semantics change, the minor version when substantive runtime content is added, and the patch version for corrections that do not change meaning.

## [Unreleased]

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

[Unreleased]: https://github.com/agentic-operating-procedure/aop-reference-harness/compare/v0.2.0...HEAD
[v0.2.0]: https://github.com/agentic-operating-procedure/aop-reference-harness/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/agentic-operating-procedure/aop-reference-harness/releases/tag/v0.1.0
