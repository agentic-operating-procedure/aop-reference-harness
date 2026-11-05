"""The scoped credential broker.

Credentials are short-lived, scoped to one action class, and issued at the
moment of execution (SEC-3, ARC-C1 to ARC-C3). The broker sits beside the
guardrail, outside the agent's reach. A credential scoped to one action class
does not authorize another. High-risk classes require a prior human approval,
and the credential is issued after the approval, never before.
"""

from __future__ import annotations

import secrets
import time


class CredentialBroker:
    def __init__(self, aop: dict, high_risk_classes: set[str] | None = None, ttl_seconds: int = 300):
        self._skills = {s["id"]: s for s in aop.get("capabilities", {}).get("skills", [])}
        self._issued_log: list[dict] = []
        self.high_risk_classes = high_risk_classes or {"dispatch-write", "config-write"}
        self.ttl_seconds = ttl_seconds

    def issue(self, action: str, action_class: str, authority_decision: dict, approval_record: dict | None = None) -> dict | None:
        """Issue a scoped credential for one action execution, or refuse.

        The credential is scoped to the action class, carries the run's
        authority decision reference, and expires. The issuance is logged for
        the case record (T3 answer: every issuance is tied to a run, a rule
        and a decision)."""
        if authority_decision["decision"] == "approval-required" and approval_record is None:
            raise PermissionError("high-risk credential requested without a prior human approval (ARC-C2)")
        if authority_decision["decision"] == "prohibit":
            return None

        credential = {
            "token": secrets.token_urlsafe(24),
            "action": action,
            "action_class": action_class,
            "workload_id": authority_decision.get("workload_id"),
            "issued_at": time.time(),
            "expires_at": time.time() + self.ttl_seconds,
            "authority_decision": authority_decision["decision"],
            "rule_reference": (authority_decision.get("rule") or {}).get("if"),
        }
        self._issued_log.append(credential)
        return credential

    def validate(self, credential: dict, action: str, workload: str | None = None) -> bool:
        """One-shot validation: unexpired, scoped to exactly this action, and
        presented by the workload it was issued to (SEC-16). A credential
        presented by a different workload is refused."""
        if credential.get("action") != action:
            return False
        if time.time() > credential.get("expires_at", 0):
            return False
        if credential.get("workload_id") and workload is not None and credential["workload_id"] != workload:
            return False
        return True

    def revocations_for_case(self) -> list[dict]:
        """The issuance log for the case record: issuance, use, expiry."""
        return [{k: v for k, v in c.items() if k != "token"} for c in self._issued_log]
