"""Erasure-compatible evidence (NM-ASR-7, CR-026).

Erasure never edits the chain. Sensitive payloads externalised to the side
store are shredded (their content becomes unrecoverable), and a tombstone
entry is appended to the chain recording who erased what and why. The record
afterwards states which replay claims survive: R1 verification of the chain
always holds; R2 reconstruction narrows for the entries whose payloads are
gone, and the narrowing is explicit.
"""

from __future__ import annotations

import hashlib
import json
import os
import time


def shred_case(store, case_id: str, reason: str, by: str) -> dict:
    """Erase one case's externalised payloads and append the tombstone.

    Returns the erasure record. Claims afterwards: R1 intact for the whole
    chain; R2 narrowed for the erased case (the decisions and outcomes
    remain; the input payloads are gone)."""
    erased = []
    if store.payload_store_path and os.path.exists(store.payload_store_path):
        with open(store.payload_store_path) as handle:
            payloads = [json.loads(line) for line in handle if line.strip()]
        kept = []
        for p in payloads:
            if p.get("case_id") == case_id:
                erased.append(p["payload_digest"])
            else:
                kept.append(p)
        if erased:
            with open(store.payload_store_path, "w") as handle:
                for p in kept:
                    handle.write(json.dumps(p) + "\n")

    store.append(case_id, store.read_all()[-1]["aop"] if store.read_all() else "unknown@v0.0.0",
                 None,
                 {"erasure": True, "payloads_erased": len(erased), "reason": reason},
                 "erasure://" + case_id,
                 None, None, "erasure-tombstone", by,
                 {"result": "recorded", "erased_payloads": erased,
                  "surviving_claims": ["R1 chain verification", "decision and outcome metadata"],
                  "withdrawn_claims": ["R2 reconstruction of erased input payloads"]})
    return {"case_id": case_id, "erased_payloads": erased, "by": by,
            "reason": reason, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
