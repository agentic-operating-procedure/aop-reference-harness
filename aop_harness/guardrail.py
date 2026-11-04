"""The bounded-execution guardrail.

This is the policy decision point and the policy enforcement point. It sits
OUTSIDE the model context: the agent proposes, this component disposes, and
nothing the agent controls can influence the decision (SEC-1, SEC-2). The
guardrail fails closed on unknown conditions, unmatched variants and
enforcement errors (SEC-5, SEC-7).
"""

from __future__ import annotations

from . import expression


class Decision:
    EXECUTE = "execute"
    APPROVAL_REQUIRED = "approval-required"
    ESCALATE = "escalate"
    PROHIBIT = "prohibit"


class Guardrail:
    def __init__(self, aop: dict):
        self.aop = aop
        self.permitted = set(aop.get("constraints", {}).get("permitted_actions", []))
        self.prohibited = set(aop.get("constraints", {}).get("prohibited_actions", []))
        self.default_class = aop.get("authority", {}).get("default_authority_class", "prohibited")
        # NM-STR-16: the decision context contains only system-attested and
        # derived facts. Each declared element binds to its runtime key (or
        # its name, in identifier form); anything else in the snapshot is
        # invisible to matching and to authority evaluation.
        self.trusted_keys = set()
        for el in aop.get("context", {}).get("elements", []):
            if el.get("trust_class") in ("system-attested", "derived"):
                key = (el.get("key") or el.get("name") or "").lower()
                self.trusted_keys.add(key)
                self.trusted_keys.add(key.replace("-", "_"))
        self._validate_closure()

    def decision_context(self, context: dict) -> dict:
        """The attested-and-derived view of the snapshot: the only context
        the decision point sees (NM-STR-16)."""
        return {k: v for k, v in context.items() if k in self.trusted_keys}

    def _validate_closure(self):
        """A guardrail that starts wider than its AOP is a defect."""
        if self.prohibited & self.permitted:
            raise ValueError("AOP governance error: an action is both permitted and prohibited")
        if self.default_class not in ("autonomous", "approval-required", "prohibited"):
            raise ValueError("AOP governance error: unknown default authority class")

    def match_variant(self, context: dict) -> tuple[dict | None, str]:
        context = self.decision_context(context)
        """Match the context snapshot to a variant (NM-STR-8). Machine-evaluable
        triggers are tested in declared order against this context; a variant
        whose trigger cannot be evaluated at all is the fallback candidate.
        Returns (variant|None, note). No match means fail closed."""
        fallback = None
        for variant in self.aop.get("structure", {}).get("variants", []):
            trigger = variant.get("trigger", "")
            try:
                if expression.evaluate(trigger, context):
                    return variant, "matched trigger %r" % trigger
            except expression.ConditionError as exc:
                # A trigger that cannot even parse (prose) is a fallback
                # candidate; a trigger that parses but reads unknown names on
                # this context simply does not match this case.
                if "not evaluable" in str(exc) or "could not be evaluated" in str(exc):
                    if fallback is None:
                        fallback = variant
                continue
        if fallback is not None:
            return fallback, "fallback to declared residual variant"
        return None, "no variant matched"

    def authorise(self, variant: dict | None, action: str, context: dict) -> dict:
        """Decide one proposed action. Returns a decision record with the rule
        applied and its provenance. This method is the whole of the agent's
        authority: what it returns is what executes, nothing else."""
        context = self.decision_context(context)
        # 1. Prohibited outright.
        if action in self.prohibited:
            return {"decision": Decision.PROHIBIT, "authority": "prohibited",
                    "rule": {"if": "action in prohibited_actions", "then": "prohibit"},
                    "provenance": None, "note": "prohibited action"}

        # 2. Outside the permitted set: not prohibited by name, but never allowed.
        if self.permitted and action not in self.permitted:
            return {"decision": Decision.ESCALATE, "authority": "unknown",
                    "rule": {"if": "action not in permitted_actions", "then": "escalate to named human decision"},
                    "provenance": None, "note": "action is outside the permitted set (NM-CON-1)"}

        # 3. Find the first matching decision rule on the matched variant.
        if variant is not None:
            for rule in variant.get("decision_rules", []):
                try:
                    if expression.evaluate(rule.get("if", ""), context):
                        return self._from_rule(rule, action, context)
                except expression.ConditionError:
                    # The rule could not be evaluated on this context: keep
                    # looking, and remember the uncertainty.
                    continue

        # 4. No rule matched: default authority class, else fail closed.
        if self.default_class == "prohibited":
            return {"decision": Decision.ESCALATE, "authority": "unknown",
                    "rule": None, "provenance": None,
                    "note": "no decision rule matched and the default class is prohibited (NM-AUT-3)"}
        return {"decision": Decision.APPROVAL_REQUIRED if self.default_class == "approval-required" else Decision.EXECUTE,
                "authority": self.default_class, "rule": {"if": "default_authority_class", "then": self.default_class},
                "provenance": None, "note": "default authority class applied (NM-AUT-3)"}

    def _from_rule(self, rule: dict, action: str, context: dict) -> dict:
        # A rule scoped with applies_to governs only the actions it names;
        # for any other action it does not match and the search continues.
        applies_to = rule.get("applies_to")
        if applies_to and action not in applies_to:
            raise expression.ConditionError("rule does not apply to this action")
        authority = rule.get("authority", "prohibited")
        if authority == "autonomous":
            decision = Decision.EXECUTE
        elif authority == "approval-required":
            decision = Decision.APPROVAL_REQUIRED
        else:
            decision = Decision.PROHIBIT
        return {"decision": decision, "authority": authority, "rule": rule,
                "provenance": rule.get("provenance"),
                "note": "matched rule %r" % rule.get("if")}
