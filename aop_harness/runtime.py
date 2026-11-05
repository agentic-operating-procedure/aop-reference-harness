"""The runtime loop: snapshot, match, authorise, execute, record, emit.

One run executes one case against one immutable AOP version (NM-STR-11). The
agent proposes actions from the variant plan; the guardrail disposes; the
harness executes what was approved, records everything, and emits the case
record to the substrate as new observation (ARC-P5). Matching selects an
observed path, not a happy path, and an unmatched case fails closed (SEC-5).
"""

from __future__ import annotations

import secrets
import time

from . import __version__ as _harness_version

from .broker import CredentialBroker


class _MatrixStore:
    """NM-VER-8: stamps the run's component matrix on every appended entry."""

    def __init__(self, store, component_matrix):
        self._store = store
        self._matrix = component_matrix

    def append(self, *args, **kwargs):
        kwargs.setdefault("component_matrix", self._matrix)
        return self._store.append(*args, **kwargs)

    def read_all(self):
        return self._store.read_all()

    def verify_chain(self):
        return self._store.verify_chain()

    @property
    def path(self):
        return self._store.path

    @property
    def payload_store_path(self):
        return getattr(self._store, 'payload_store_path', None)
from .caserecord import CaseRecordStore
from .evidence import ApproverPolicy, EscalationDispatch, build_evidence_bundle
from .guardrail import Decision, Guardrail

ACTION_CLASSES = {
    "correlate-alarms": "monitoring-read",
    "loopback-test": "line-test-execute",
    "resolve-fault": "monitoring-read",
    "dispatch-field-crew": "dispatch-write",
    "notify-planning": "planning-write",
    "reconcile-inventory": "inventory-write",
}

# RA-8: the retry class per action. Deployment configuration in a real
# estate; the reference table demonstrates all three classes.
ACTION_RETRY_CLASS = {
    "correlate-alarms": "idempotent",
    "loopback-test": "idempotent",
    "resolve-fault": "idempotent",
    "notify-planning": "idempotent",
    "reconcile-inventory": "reconciling",
    "dispatch-field-crew": "manual",
}


class RunOutcome:
    ACHIEVED = "achieved"
    PARTIALLY_ACHIEVED = "partially_achieved"
    NOT_ACHIEVED = "not_achieved"
    ACCEPTED_WITH_DEVIATION = "accepted_with_deviation"
    INCONCLUSIVE = "inconclusive"


class Runtime:
    def __init__(self, aop: dict, record_path: str, approver: ApproverPolicy | None = None,
                 payload_store_path: str | None = None):
        self.aop = aop
        self.aop_ref = "%s@%s" % (aop["aop"], aop["version"])
        self.guardrail = Guardrail(aop)
        self.broker = CredentialBroker(aop)
        self.dispatch = EscalationDispatch(aop.get("coordination", {}).get("escalation_routes", []))
        self.approver = approver or ApproverPolicy()
        # SEC-16: workload identity per run.
        self.workload_id = "wl-" + secrets.token_urlsafe(8)
        # NM-VER-8: the component matrix every entry carries.
        self.component_matrix = {
            "harness": "aop-reference-harness " + _harness_version,
            "aop_ref": self.aop_ref,
            "workload_id": self.workload_id,
            "policy_bundle": "digest of the bound AOP document (ARC-TB1 records the digest per run)",
        }
        self.store = _MatrixStore(CaseRecordStore(record_path, payload_store_path=payload_store_path),
                                  self.component_matrix)
        self.accountable_owner = aop.get("governance", {}).get("accountable_owner")
        # NM-VER-6: an optional revocation provider; called with the bound ref
        # before a run binds. Returns a dict or None.
        self.revocation_provider = None
        # CR-025: the incident lifecycle state.
        self.incidents: list[dict] = []
        self.halted = False
        self.stats = {"runs": 0, "executed": 0, "approvals": 0, "escalations": 0, "prohibited": 0, "fail_closed": 0, "holds": 0, "budget_escalations": 0, "duplicates_answered": 0}
        # RA-10: executed action digests per case, for duplicate delivery.
        self._executed_digests: dict[str, dict] = {}
        # NM-CRD-4: per-case usage counters keyed by action class.
        self._class_usage: dict[str, int] = {}

    def declare_incident(self, incident_type: str, severity: str, by: str) -> dict:
        """CR-025: declare an incident: the domain holds at the enforcement
        point, the incident is recorded, and recovery runs the full path
        (integrity check, then the owner-gated resumption)."""
        incident = {"type": incident_type, "severity": severity, "by": by,
                    "declared_at": time.time(), "state": "responding"}
        self.incidents.append(incident)
        self.halted = True
        return incident

    def recover(self, role: str) -> dict:
        """CR-025: recovery requires the integrity check to pass and the
        accountable owner's resumption decision. A broken chain refuses."""
        intact, problems = self.store.verify_chain()
        if not intact:
            return {"resumed": False, "reason": "case record integrity check failed: %s" % "; ".join(problems[:2])}
        if not self.resume(role):
            return {"resumed": False, "reason": "resumption requires the accountable owner (SEC-15)"}
        for incident in self.incidents:
            if incident["state"] != "recovered":
                incident["state"] = "recovered"
                incident["recovered_by"] = role
        return {"resumed": True, "incidents_recovered": len(self.incidents)}

    def record_migration(self, original_case_id: str, new_case_id: str, reason: str) -> dict:
        """RA-23: mark on the original record that the case migrated to a
        linked new run. Append-only: the original entries are never rewritten."""
        entries = self.store.read_all()
        original = next((e for e in entries if e.get("case_id") == original_case_id), None)
        if original is None:
            raise ValueError("cannot migrate: no record for %s" % original_case_id)
        return self.store.append(original_case_id, self.aop_ref, None,
                                 {"migration": True, "new_case_id": new_case_id, "reason": reason},
                                 original.get("context_snapshot", "erasure://" + original_case_id),
                                 None, None, "migrated", None,
                                 {"result": RunOutcome.INCONCLUSIVE,
                                  "note": "case migrated to %s; linked run carries the work (RA-23)" % new_case_id})

    def emergency_stop(self, role: str) -> dict:
        """SEC-15: a named role halts every subsequent run in the domain at
        the enforcement point. Resumption requires the accountable owner."""
        self.halted = True
        return {"stopped_by": role, "resumption_requires": self.accountable_owner}

    def resume(self, role: str) -> bool:
        """Only the accountable owner may authorise resumption (SEC-15)."""
        if role == self.accountable_owner:
            self.halted = False
            return True
        return False

    def run_case(self, case: dict, agent) -> dict:
        """Execute one case. The agent proposes; this loop disposes."""
        case_id = case["case_id"]
        context = dict(case.get("context", {}))
        snapshot_ref = "cg://case/%s@%s" % (case_id, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        self.stats["runs"] += 1

        ref = self.aop_ref
        if self.revocation_provider is not None:
            state = self.revocation_provider(ref)
            if state and state.get("revoked"):
                # NM-VER-6: a revoked version holds at the enforcement point.
                self.stats["holds"] += 1
                self.store.append(case_id, ref, None, context, snapshot_ref,
                                  None, None, "hold", None,
                                  {"result": RunOutcome.INCONCLUSIVE,
                                   "note": "bound version revoked: %s" % state.get("reason", "")})
                return {"case_id": case_id, "outcome": RunOutcome.INCONCLUSIVE, "held": True}
        if self.halted:
            # SEC-15: an emergency stop halts runs at the enforcement point.
            self.stats["holds"] += 1
            self.store.append(case_id, self.aop_ref, None, context, snapshot_ref,
                              None, None, "hold", None,
                              {"result": RunOutcome.INCONCLUSIVE, "note": "domain halted by emergency stop"})
            return {"case_id": case_id, "outcome": RunOutcome.INCONCLUSIVE, "held": True}

        try:
            variant, match_note = self.guardrail.match_variant(context)
        except Exception as exc:  # noqa: BLE001
            # SEC-14: enforcement unavailability holds the run. It never proceeds.
            self.stats["holds"] += 1
            self.store.append(case_id, self.aop_ref, None, context, snapshot_ref,
                              None, None, "hold", None,
                              {"result": RunOutcome.INCONCLUSIVE, "note": "enforcement unavailable: %s" % exc})
            return {"case_id": case_id, "outcome": RunOutcome.INCONCLUSIVE, "held": True}
        if variant is None:
            # NM-STR-9: no matching variant fails closed.
            self.stats["fail_closed"] += 1
            self.store.append(case_id, self.aop_ref, None, context, snapshot_ref,
                              None, None, "escalate", None,
                              {"result": RunOutcome.INCONCLUSIVE, "note": "unmatched variant: " + match_note})
            return {"case_id": case_id, "outcome": RunOutcome.INCONCLUSIVE, "fail_closed": True}

        # The agent proposes from the matched variant's plan. What executes is
        # whatever the guardrail approves, nothing else.
        plan = agent.propose(variant.get("steps", []), context)
        outcome = RunOutcome.ACHIEVED
        notes = [match_note]

        for action in plan:
            try:
                decision = self.guardrail.irreversibility_verdict(action, self.guardrail.authorise(variant, action, context))
            except Exception as exc:  # noqa: BLE001
                # SEC-14: hold, record, escalate; never proceed on a broken check.
                self.stats["holds"] += 1
                notes.append("%s held: enforcement unavailable" % action)
                outcome = RunOutcome.INCONCLUSIVE
                self.store.append(case_id, self.aop_ref, variant["id"], context, snapshot_ref,
                                  None, None, "hold", None,
                                  {"result": outcome, "note": "enforcement unavailable: %s" % exc})
                break

            if decision["decision"] == Decision.PROHIBIT:
                self.stats["prohibited"] += 1
                notes.append("%s prohibited: %s" % (action, decision["note"]))
                outcome = RunOutcome.NOT_ACHIEVED
                self.store.append(case_id, self.aop_ref, variant["id"], context, snapshot_ref,
                                  decision["rule"], decision["provenance"], "prohibit", None,
                                  {"result": outcome, "note": decision["note"]})
                continue

            if decision["decision"] == Decision.ESCALATE:
                self.stats["escalations"] += 1
                bundle = build_evidence_bundle(case_id, self.aop, decision, context, action)
                target = self.dispatch.route_for(decision["authority"])
                ruling = self.dispatch.dispatch(bundle, target, self.approver)
                ruling["ruled_at"] = ruling["dispatched_at"]  # reference approver rules immediately
                notes.append("%s escalated to %s: %s" % (action, target, ruling["ruling"]["note"]))
                if ruling["ruling"].get("outcome") != "approve":
                    outcome = RunOutcome.NOT_ACHIEVED if outcome == RunOutcome.ACHIEVED else outcome
                    self.store.append(case_id, self.aop_ref, variant["id"], context, snapshot_ref,
                                      decision["rule"], decision["provenance"], ruling["ruling"].get("outcome", "reject"), ruling["approver"],
                                      {"result": outcome, "note": ruling["ruling"].get("note", "not approved")})
                    break
                decision = {**decision, "decision": Decision.EXECUTE, "note": "approved by " + ruling["approver"]}

            if decision["decision"] == Decision.APPROVAL_REQUIRED:
                self.stats["approvals"] += 1
                bundle = build_evidence_bundle(case_id, self.aop, decision, context, action,
                                               action_digest=self.guardrail.action_digest(action, parameters={k: context.get(k) for k in sorted(self.guardrail.trusted_keys) if context.get(k) is not None}))
                target = self.dispatch.route_for(decision["authority"])
                ruling = self.dispatch.dispatch(bundle, target, self.approver,
                                                fallback_role=(self.aop.get("assurance", {}).get("oversight") or {}).get("fallback_role"))
                ruling["ruled_at"] = ruling["dispatched_at"]
                notes.append("%s approval required: %s" % (action, ruling["ruling"]["note"]))
                if ruling["ruling"].get("outcome") != "approve":
                    outcome = RunOutcome.NOT_ACHIEVED if outcome == RunOutcome.ACHIEVED else outcome
                    self.store.append(case_id, self.aop_ref, variant["id"], context, snapshot_ref,
                                      decision["rule"], decision["provenance"], ruling["ruling"].get("outcome", "reject"), ruling["approver"],
                                      {"result": outcome, "note": ruling["ruling"].get("note", "not approved")})
                    break
                self.store.append(case_id, self.aop_ref, variant["id"], context, snapshot_ref,
                                  decision["rule"], decision["provenance"], "approval", ruling["approver"],
                                  {"result": RunOutcome.PARTIALLY_ACHIEVED, "note": "approved, executing"})
                decision = {**decision, "decision": Decision.EXECUTE, "note": "approved by " + ruling["approver"]}

            # RA-6: the decision binds to the action digest; a credential
            # authorises the digest, not the action name alone.
            digest = self.guardrail.action_digest(action, parameters={k: context.get(k) for k in self.guardrail.trusted_keys})
            if digest in self._executed_digests:
                # RA-10: duplicate delivery is answered from the record.
                self.stats["duplicates_answered"] += 1
                notes.append("%s duplicate delivery answered from the record (RA-10)" % action)
                continue

            # NM-CRD-4: the budget verdict is checked beside the authority check.
            budget = self.guardrail.budget_verdict(action, self._class_usage)
            if budget is not None:
                self.stats["budget_escalations"] += 1
                notes.append("%s %s" % (action, budget["note"]))
                self.store.append(case_id, self.aop_ref, variant["id"], context, snapshot_ref,
                                  budget["rule"], None, "escalate", None,
                                  {"result": RunOutcome.PARTIALLY_ACHIEVED, "note": budget["note"]})
                outcome = RunOutcome.PARTIALLY_ACHIEVED
                continue

            # RA-21: the canonical payload is validated against the declared
            # parameter schema immediately before execution.
            params = {k: context.get(k) for k in sorted(self.guardrail.trusted_keys) if context.get(k) is not None}
            pfail = self.guardrail.parameter_verdict(action, params)
            if pfail is not None:
                self.stats["fail_closed"] += 1
                notes.append("%s %s" % (action, pfail["note"]))
                self.store.append(case_id, self.aop_ref, variant["id"], context, snapshot_ref,
                                  pfail["rule"], None, "escalate", None,
                                  {"result": RunOutcome.PARTIALLY_ACHIEVED, "note": pfail["note"]})
                outcome = RunOutcome.PARTIALLY_ACHIEVED
                continue

            # Execute with a scoped credential (SEC-3), scoped to the digest.
            credential = self.broker.issue(action, ACTION_CLASSES.get(action, "default"), decision, approval_record={"approved": True})
            if credential is not None:
                credential["workload_id"] = self.workload_id
            if credential is None or not self.broker.validate(credential, action, workload=self.workload_id):
                self.stats["fail_closed"] += 1
                notes.append("%s failed closed at the credential broker" % action)
                outcome = RunOutcome.INCONCLUSIVE
                self.store.append(case_id, self.aop_ref, variant["id"], context, snapshot_ref,
                                  decision["rule"], decision["provenance"], "fail-closed", None,
                                  {"result": outcome, "note": "credential broker refused"})
                break
            self._executed_digests[digest] = {"action": action, "decision": decision["decision"]}
            self._class_usage[ACTION_CLASSES.get(action, "default")] = self._class_usage.get(ACTION_CLASSES.get(action, "default"), 0) + 1
            self.stats["executed"] += 1
            notes.append("%s executed under digest-scoped credential %s" % (action, digest[:19]))

        final_result = case.get("outcome", {}).get("result", outcome) if outcome == RunOutcome.ACHIEVED else outcome
        self.store.append(case_id, self.aop_ref, variant["id"], context, snapshot_ref,
                          None, None, "complete", None,
                          {"result": final_result, "notes": notes},
                          component_matrix=self.component_matrix)
        return {"case_id": case_id, "outcome": final_result, "variant": variant["id"], "notes": notes}

    def emit(self) -> list[dict]:
        """The case records are the emission: execution evidence becomes new
        observation for the substrate (ARC-P5). Returns the records."""
        return self.store.read_all()
