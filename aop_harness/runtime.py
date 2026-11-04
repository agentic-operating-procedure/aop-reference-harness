"""The runtime loop: snapshot, match, authorise, execute, record, emit.

One run executes one case against one immutable AOP version (NM-STR-11). The
agent proposes actions from the variant plan; the guardrail disposes; the
harness executes what was approved, records everything, and emits the case
record to the substrate as new observation (ARC-P5). Matching selects an
observed path, not a happy path, and an unmatched case fails closed (SEC-5).
"""

from __future__ import annotations

import time

from .broker import CredentialBroker
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
    def __init__(self, aop: dict, record_path: str, approver: ApproverPolicy | None = None):
        self.aop = aop
        self.aop_ref = "%s@%s" % (aop["aop"], aop["version"])
        self.guardrail = Guardrail(aop)
        self.broker = CredentialBroker(aop)
        self.dispatch = EscalationDispatch(aop.get("coordination", {}).get("escalation_routes", []))
        self.approver = approver or ApproverPolicy()
        self.store = CaseRecordStore(record_path)
        self.accountable_owner = aop.get("governance", {}).get("accountable_owner")
        self.halted = False
        self.stats = {"runs": 0, "executed": 0, "approvals": 0, "escalations": 0, "prohibited": 0, "fail_closed": 0, "holds": 0, "budget_escalations": 0, "duplicates_answered": 0}
        # RA-10: executed action digests per case, for duplicate delivery.
        self._executed_digests: dict[str, dict] = {}
        # NM-CRD-4: per-case usage counters keyed by action class.
        self._class_usage: dict[str, int] = {}

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
                notes.append("%s escalated to %s: %s" % (action, target, ruling["ruling"]["note"]))
                if not ruling["ruling"].get("approve"):
                    outcome = RunOutcome.NOT_ACHIEVED if outcome == RunOutcome.ACHIEVED else outcome
                    self.store.append(case_id, self.aop_ref, variant["id"], context, snapshot_ref,
                                      decision["rule"], decision["provenance"], "escalate", ruling["approver"],
                                      {"result": outcome, "note": "escalation rejected"})
                    break
                decision = {**decision, "decision": Decision.EXECUTE, "note": "approved by " + ruling["approver"]}

            if decision["decision"] == Decision.APPROVAL_REQUIRED:
                self.stats["approvals"] += 1
                bundle = build_evidence_bundle(case_id, self.aop, decision, context, action)
                target = self.dispatch.route_for(decision["authority"])
                ruling = self.dispatch.dispatch(bundle, target, self.approver)
                notes.append("%s approval required: %s" % (action, ruling["ruling"]["note"]))
                if not ruling["ruling"].get("approve"):
                    outcome = RunOutcome.NOT_ACHIEVED if outcome == RunOutcome.ACHIEVED else outcome
                    self.store.append(case_id, self.aop_ref, variant["id"], context, snapshot_ref,
                                      decision["rule"], decision["provenance"], "escalate", ruling["approver"],
                                      {"result": outcome, "note": "approval rejected"})
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

            # Execute with a scoped credential (SEC-3), scoped to the digest.
            credential = self.broker.issue(action, ACTION_CLASSES.get(action, "default"), decision, approval_record={"approved": True})
            if credential is None or not self.broker.validate(credential, action):
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
                          {"result": final_result, "notes": notes})
        return {"case_id": case_id, "outcome": final_result, "variant": variant["id"], "notes": notes}

    def emit(self) -> list[dict]:
        """The case records are the emission: execution evidence becomes new
        observation for the substrate (ARC-P5). Returns the records."""
        return self.store.read_all()
