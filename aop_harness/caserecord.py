"""The append-only, tamper-evident case record (SEC-8, NM-ASR-1, SEC-10).

Records are appended to a JSONL file as a hash chain: each entry carries the
hash of its predecessor, so any later edit or deletion breaks the chain and is
detectable. The agent has no writer access to this store; only the harness
appends. Every decision is replayable from the record alone.
"""

from __future__ import annotations

import hashlib
import json
import os
import time

MANDATORY_FIELDS = ["inputs", "context_snapshot", "rule", "provenance", "decision", "approver", "outcome"]


def _entry_hash(entry: dict) -> str:
    material = {k: v for k, v in entry.items() if k not in ("hash",)}
    return hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()


class CaseRecordStore:
    def __init__(self, path: str):
        self.path = path
        self._seq = 0
        self._prev_hash = "0" * 64
        if os.path.exists(path):
            with open(path) as handle:
                for line in handle:
                    line = line.strip()
                    if line:
                        entry = json.loads(line)
                        self._seq = entry["seq"]
                        self._prev_hash = entry["hash"]

    def append(self, case_id: str, aop_ref: str, variant_id: str | None, inputs: dict,
               context_snapshot: str, rule: dict | None, provenance: dict | None,
               decision: str, approver: str | None, outcome: dict) -> dict:
        # Structural completeness: the record always carries every mandatory
        # field; rule, provenance and approver may be None when genuinely
        # absent from the decision, but the fields themselves are never
        # omitted (NM-ASR-1, SEC-6: no path proceeds without a record).
        missing = [f for f in ("case_id", "inputs", "context_snapshot", "decision", "outcome")
                   if locals().get(f) is None]
        if missing:
            raise ValueError("case record would be incomplete: missing %s (NM-ASR-1)" % ", ".join(missing))
        entry = {
            "seq": self._seq + 1,
            "appended_at": time.time(),
            "case_id": case_id,
            "aop": aop_ref,
            "variant": variant_id,
            "inputs": inputs,
            "context_snapshot": context_snapshot,
            "rule": rule,
            "provenance": provenance,
            "decision": decision,
            "approver": approver,
            "outcome": outcome,
            "prev_hash": self._prev_hash,
        }
        entry["hash"] = _entry_hash(entry)
        with open(self.path, "a") as handle:
            handle.write(json.dumps(entry) + "\n")
        self._seq = entry["seq"]
        self._prev_hash = entry["hash"]
        return entry

    def read_all(self) -> list[dict]:
        if not os.path.exists(self.path):
            return []
        with open(self.path) as handle:
            return [json.loads(line) for line in handle if line.strip()]

    def verify_chain(self) -> tuple[bool, list[str]]:
        """Recompute the chain over the whole file. Any edit, deletion or
        reordering breaks it (SEC-8)."""
        problems = []
        expected_prev = "0" * 64
        entries = self.read_all()
        for index, entry in enumerate(entries, start=1):
            if entry.get("seq") != index:
                problems.append("entry %d has seq %s" % (index, entry.get("seq")))
            if entry.get("prev_hash") != expected_prev:
                problems.append("entry %d breaks the chain: prev_hash mismatch" % index)
            if entry.get("hash") != _entry_hash(entry):
                problems.append("entry %d content does not match its hash" % index)
            expected_prev = entry.get("hash", expected_prev)
        return (not problems), problems
