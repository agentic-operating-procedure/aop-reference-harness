"""Replay: the three levels of the evidence and replay semantics (RP-1 to RP-7).

R1 record verification and R2 decision-trace reconstruction run from the case
record alone, without trusting the harness or agent that produced it. R3
controlled re-execution is deliberately NOT implemented here: it requires its
own authorization under the AOP's authority model, and a record is not an
authorization (RP-2).
"""

from __future__ import annotations

import json
from pathlib import Path

from .caserecord import CaseRecordStore, MANDATORY_FIELDS

LEVELS = ("R1", "R2", "R3")


def verify_record(path: str) -> dict:
    """R1: the record is intact. Chain verifies, mandatory fields present."""
    store = CaseRecordStore(path)
    intact, problems = store.verify_chain()
    entries = store.read_all()
    incomplete = [e["seq"] for e in entries if any(f not in e for f in MANDATORY_FIELDS)]
    return {
        "level": "R1",
        "verdict": "verified" if intact and not incomplete else "failed",
        "entries": len(entries),
        "problems": problems + (["incomplete fields at %s" % incomplete] if incomplete else []),
    }


def reconstruct_trace(path: str, case_id: str, aop_rule_index: dict | None = None) -> dict:
    """R2: re-derive and explain the decisions for one case from the record
    alone. aop_rule_index optionally maps 'if' strings to their ratified
    status in the bound AOP version, so the reconstruction can check the rule
    was one the record's AOP version could have applied."""
    store = CaseRecordStore(path)
    entries = [e for e in store.read_all() if e.get("case_id") == case_id]
    if not entries:
        return {"level": "R2", "verdict": "no-record", "case_id": case_id}

    trace = []
    checks = {"rule_reconstructible": True, "digest_present": True}
    tombstones = [e for e in entries if e.get("decision") == "erasure-tombstone"]
    for e in entries:
        rule = e.get("rule")
        decision = e.get("decision")
        step = {
            "seq": e["seq"],
            "decision": decision,
            "approver": e.get("approver"),
            "variant": e.get("variant"),
            "context_snapshot": e.get("context_snapshot"),
            "inputs_digest_reference": e.get("provenance"),
            "outcome": e.get("outcome"),
        }
        if decision in ("execute", "approval-required", "prohibit", "escalate"):
            if rule is None:
                checks["rule_reconstructible"] = False
                step["reconstruction_note"] = "decision without a recorded rule: not R2-reconstructible"
            else:
                step["rule_if"] = rule.get("if")
                if aop_rule_index is not None and rule.get("if") not in aop_rule_index:
                    checks["rule_reconstructible"] = False
                    step["reconstruction_note"] = "rule not present in the bound AOP version's rule set"
        trace.append(step)

    verdict = "reconstructed" if checks["rule_reconstructible"] else "partial"
    result = {
        "level": "R2",
        "verdict": verdict,
        "case_id": case_id,
        "checks": checks,
        "states_observed": [t["decision"] for t in trace],
        "trace": trace,
        "r3_available": False,
        "r3_note": "controlled re-execution requires its own authorization decision (RP-2); a record is not an authorization",
    }
    if tombstones:
        # NM-ASR-7 / RP-5: the record states which claims survive and which
        # are withdrawn after erasure.
        latest = tombstones[-1]
        result["verdict"] = "narrowed"
        result["erasure"] = {"by": latest.get("approver"),
                             "surviving_claims": (latest.get("outcome") or {}).get("surviving_claims", []),
                             "withdrawn_claims": (latest.get("outcome") or {}).get("withdrawn_claims", [])}
    return result


def verify_third_party(record_path: str, aop_rule_index: dict, case_ids: list[str] | None = None) -> dict:
    """RP-7: verification without trusting the producer. The verifier needs
    the record, the rule index of the bound AOP version, and nothing else."""
    r1 = verify_record(record_path)
    store = CaseRecordStore(record_path)
    ids = case_ids or sorted({e["case_id"] for e in store.read_all()})
    traces = [reconstruct_trace(record_path, cid, aop_rule_index) for cid in ids]
    return {
        "r1": r1,
        "r2": {"cases": len(traces),
               "reconstructed": sum(1 for t in traces if t["verdict"] == "reconstructed"),
               "partial": sum(1 for t in traces if t["verdict"] == "partial")},
        "level_claimed": "R2",
        "verdict": "verified" if r1["verdict"] == "verified" else "failed",
    }
