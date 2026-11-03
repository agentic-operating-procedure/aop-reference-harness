# Changelog

All notable changes to this repository are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning is semantic: the major version changes when the runtime loop sequence or the enforcement semantics change, the minor version when substantive runtime content is added, and the patch version for corrections that do not change meaning.

## [Unreleased]

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

[Unreleased]: https://github.com/agentic-operating-procedure/aop-reference-harness/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/agentic-operating-procedure/aop-reference-harness/releases/tag/v0.1.0
