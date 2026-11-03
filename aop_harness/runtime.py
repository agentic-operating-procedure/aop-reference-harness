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
        self.stats = {"runs": 0, "executed": 0, "approvals": 0, "escalations": 0, "prohibited": 0, "fail_closed": 0}

    def run_case(self, case: dict, agent) -> dict:
        """Execute one case. The agent proposes; this loop disposes."""
        case_id = case["case_id"]
        context = dict(case.get("context", {}))
        snapshot_ref = "cg://case/%s@%s" % (case_id, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        self.stats["runs"] += 1

        variant, match_note = self.guardrail.match_variant(context)
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
            decision = self.guardrail.authorise(variant, action, context)

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

            # Execute with a scoped credential (SEC-3).
            credential = self.broker.issue(action, ACTION_CLASSES.get(action, "default"), decision, approval_record={"approved": True})
            if credential is None or not self.broker.validate(credential, action):
                self.stats["fail_closed"] += 1
                notes.append("%s failed closed at the credential broker" % action)
                outcome = RunOutcome.INCONCLUSIVE
                self.store.append(case_id, self.aop_ref, variant["id"], context, snapshot_ref,
                                  decision["rule"], decision["provenance"], "fail-closed", None,
                                  {"result": outcome, "note": "credential broker refused"})
                break
            self.stats["executed"] += 1
            notes.append("%s executed under scoped credential" % action)

        final_result = case.get("outcome", {}).get("result", outcome) if outcome == RunOutcome.ACHIEVED else outcome
        self.store.append(case_id, self.aop_ref, variant["id"], context, snapshot_ref,
                          None, None, "complete", None,
                          {"result": final_result, "notes": notes})
        return {"case_id": case_id, "outcome": final_result, "variant": variant["id"], "notes": notes}

    def emit(self) -> list[dict]:
        """The case records are the emission: execution evidence becomes new
        observation for the substrate (ARC-P5). Returns the records."""
        return self.store.read_all()
