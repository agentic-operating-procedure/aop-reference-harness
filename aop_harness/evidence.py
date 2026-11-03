"""Evidence bundles and escalation dispatch.

The evidence bundle is what the approver sees before deciding (SEC-9): the
proposed action, the triggering rule, that rule's observed provenance, the
baseline comparison, and the case context. The approver rules on a case, not
on a mystery. The dispatch is the oversee mechanism: the human decides, and
the agent does not proceed on its own judgement while the escalation is open.
"""

from __future__ import annotations

import time


def build_evidence_bundle(case_id: str, aop: dict, authority_decision: dict, context: dict, proposed_action: str) -> dict:
    rule = authority_decision.get("rule") or {}
    baseline = aop.get("assurance", {}).get("human_baseline", {})
    bundle = {
        "case_id": case_id,
        "aop": "%s@%s" % (aop["aop"], aop["version"]),
        "proposed_action": {
            "action": proposed_action,
            "parameters": dict(context),
        },
        "triggering_rule": {
            "if": rule.get("if"),
            "then": rule.get("then"),
            "authority": authority_decision.get("authority"),
        },
        "rule_provenance": authority_decision.get("provenance") or {"observed_cases": None, "path_frequency": None},
        "context_snapshot": "cg://case/%s@%s" % (case_id, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())),
        "baseline_comparison": {
            "baseline": baseline.get("metrics", []),
            "projection": {"note": "reference harness projects no improvement claim; the evaluation tier owns that claim"},
        },
        "decision": "human-approval",
        "note": authority_decision.get("note"),
    }
    return bundle


class EscalationDispatch:
    """Dispatches evidence bundles to the target role and records the ruling.

    In this reference harness the human is simulated by an Approver policy
    object. The interface is the point: a real deployment replaces the
    policy with a person, and nothing else changes."""

    def __init__(self, routes: list[dict]):
        self.routes = {r["authority_class"]: r for r in routes}
        self.log: list[dict] = []

    def dispatch(self, bundle: dict, target_role: str, approver_policy) -> dict:
        record = {
            "dispatched_at": time.time(),
            "target_role": target_role,
            "case_id": bundle["case_id"],
            "bundle": bundle,
        }
        ruling = approver_policy.rule_on(bundle)
        record["approver"] = ruling.get("approver", target_role)
        record["ruling"] = ruling
        self.log.append(record)
        return record

    def route_for(self, authority: str, default_role: str = "on-call-engineer") -> str:
        route = self.routes.get(authority) or self.routes.get("unknown")
        return (route or {}).get("target_role", default_role)


class ApproverPolicy:
    """Reference human-in-the-loop policy: approve when the rule's provenance
    shows the path was observed, otherwise reject. A real approver is a person;
    the bundle is what they rule on."""

    def __init__(self, name: str = "shift-supervisor:simulated"):
        self.name = name

    def rule_on(self, bundle: dict) -> dict:
        provenance = bundle.get("rule_provenance") or {}
        observed = provenance.get("observed_cases") or 0
        if observed and observed > 0:
            return {"approver": self.name, "approve": True,
                    "note": "path observed in %s cases; approving" % observed}
        return {"approver": self.name, "approve": False,
                "note": "no observed provenance on the triggering rule; rejecting (CC-6)"}
