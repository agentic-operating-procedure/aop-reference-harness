"""Evidence bundles and escalation dispatch.

The evidence bundle is what the approver sees before deciding (SEC-9): the
proposed action, the triggering rule, that rule's observed provenance, the
baseline comparison, and the case context. The approver rules on a case, not
on a mystery. The dispatch is the oversee mechanism: the human decides, and
the agent does not proceed on its own judgement while the escalation is open.
"""

from __future__ import annotations

import time


def build_evidence_bundle(case_id: str, aop: dict, authority_decision: dict, context: dict, proposed_action: str, action_digest: str | None = None) -> dict:
    rule = authority_decision.get("rule") or {}
    baseline = aop.get("assurance", {}).get("human_baseline", {})
    sla = (aop.get("assurance", {}).get("oversight") or {}).get("sla_seconds")
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
    if action_digest:
        # RA-15: the approval binds to the canonical action digest.
        bundle["action_digest"] = action_digest
    if sla:
        bundle["expiry"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + sla))
    return bundle


class EscalationDispatch:
    """Dispatches evidence bundles to the target role and records the ruling.

    RA-15 to RA-19: the ruling is an approval object bound to the action
    digest with an expiry; the interface carries the four outcomes; a
    non-response routes to the fallback role and never approves; canary
    bundles detect rubber-stamping."""

    OUTCOMES = ("approve", "reject", "request-changes", "defer")

    def __init__(self, routes: list[dict], oversight: dict | None = None):
        self.routes = {r["authority_class"]: r for r in routes}
        self.oversight = oversight or {}
        self.log: list[dict] = []
        self.canary_log: list[dict] = []

    def dispatch(self, bundle: dict, target_role: str, approver_policy, fallback_role: str | None = None) -> dict:
        record = {
            "dispatched_at": time.time(),
            "target_role": target_role,
            "case_id": bundle["case_id"],
            "bundle": bundle,
        }
        ruling = approver_policy.rule_on(bundle)
        outcome = ruling.get("outcome")
        if outcome not in self.OUTCOMES:
            # RA-16: the four-outcome interface; anything else is non-response
            # and routes to the fallback role. Silence never approves.
            fb = fallback_role or self.oversight.get("fallback_role", "on-call-engineer")
            ruling = {"approver": "fallback:" + fb, "outcome": "defer",
                      "note": "no response within the SLA; routed to %s (RA-16)" % fb}
            record["routed_to_fallback"] = True
            record["ruling"] = ruling
            self.log.append(record)
            return record
        record["approver"] = ruling.get("approver", target_role)
        record["ruling"] = ruling
        self.log.append(record)
        # RA-19: canary detection. A canary bundle (declared in its provenance)
        # must be rejected; approving one is rubber-stamping and raises the alert.
        prov = bundle.get("rule_provenance") or {}
        if prov.get("canary"):
            self.canary_log.append({"case_id": bundle["case_id"], "outcome": outcome,
                                    "approver": record["approver"],
                                    "alert": outcome == "approve"})
        return record

    def route_for(self, authority: str, default_role: str = "on-call-engineer") -> str:
        route = self.routes.get(authority) or self.routes.get("unknown")
        return (route or {}).get("target_role", default_role)

    def oversight_metrics(self) -> dict:
        """RA-19: approval rate, time-to-approve, override rate, canary alert."""
        ruled = [r for r in self.log if r.get("ruling", {}).get("outcome") in self.OUTCOMES]
        approvals = [r for r in ruled if r["ruling"]["outcome"] == "approve"]
        rejections = [r for r in ruled if r["ruling"]["outcome"] == "reject"]
        times = [r.get("ruled_at", r["dispatched_at"]) - r["dispatched_at"] for r in ruled if r.get("ruled_at")]
        canary_approved = [c for c in self.canary_log if c["alert"]]
        return {
            "rulings": len(ruled),
            "approval_rate": round(len(approvals) / len(ruled), 3) if ruled else None,
            "rejection_rate": round(len(rejections) / len(ruled), 3) if ruled else None,
            "mean_time_to_approve_seconds": round(sum(times) / len(times), 3) if times else None,
            "canaries_dispatched": len(self.canary_log),
            "canaries_approved": len(canary_approved),
            "failing_approver_alert": any(canary_approved),
            "alert_detail": canary_approved,
        }


class ApproverPolicy:
    """Reference human-in-the-loop policy with the four-outcome interface.
    Approves when the rule's provenance shows the path was observed and the
    bundle is not a canary; rejects canaries and unprovenanced rules; defers
    when configured to simulate non-response. A real approver is a person;
    the bundle is what they rule on."""

    def __init__(self, name: str = "shift-supervisor:simulated", defer_all: bool = False):
        self.name = name
        self.defer_all = defer_all

    def rule_on(self, bundle: dict) -> dict:
        if self.defer_all:
            return {"approver": self.name, "outcome": "defer",
                    "note": "approver non-response simulation"}
        provenance = bundle.get("rule_provenance") or {}
        if provenance.get("canary"):
            # RA-19: the correct ruling on an injected test escalation.
            return {"approver": self.name, "outcome": "reject",
                    "note": "canary detected; rejecting the injected escalation"}
        observed = provenance.get("observed_cases") or 0
        if observed and observed > 0:
            return {"approver": self.name, "outcome": "approve",
                    "note": "path observed in %s cases; approving" % observed}
        return {"approver": self.name, "outcome": "reject",
                "note": "no observed provenance on the triggering rule; rejecting (CC-6)"}
