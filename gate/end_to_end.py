#!/usr/bin/env python3
"""The Phase 4 end-to-end gate.

One procedure compiles end to end and executes under the guardrail with a
complete case record. The gate orchestrates the three Wave 4 repositories:

  1. aop-toolkit     compile the fixture SOP + case corpus + manifest into an AOP
  2. aop-toolkit     lint the compiled AOP against the aop-spec schema and clauses
  3. aop-registry    publish it immutably, resolve it, verify its provenance chain
  4. aop-reference-harness  execute the observed corpus under the compiled AOP
  5. aop-reference-harness  verify the case record: complete fields, intact chain

Exit 0 with a GATE PASS report, exit 1 otherwise.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
HARNESS_HOME = HERE.parent
AOP_HOME = HARNESS_HOME.parent
TOOLKIT_HOME = AOP_HOME / "aop-toolkit"
REGISTRY_HOME = AOP_HOME / "aop-registry"

sys.path.insert(0, str(HARNESS_HOME))
sys.path.insert(0, str(REGISTRY_HOME))

from aop_harness.agent import ScriptedAgent          # noqa: E402
from aop_harness.caserecord import CaseRecordStore   # noqa: E402
from aop_harness.runtime import Runtime              # noqa: E402
from aop_registry.catalogue import Registry          # noqa: E402

MANDATORY_RECORD_FIELDS = ["inputs", "context_snapshot", "rule", "provenance", "decision", "approver", "outcome"]


def run(cmd: list[str], cwd: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)


def main() -> int:
    report: list[tuple[str, bool, str]] = []
    work = tempfile.mkdtemp(prefix="aop-phase4-gate-")
    compiled = os.path.join(work, "AP-LINE-001.compiled.json")
    registry_root = os.path.join(work, "registry")
    record_path = os.path.join(work, "case-record.jsonl")

    # 1. Compile.
    result = run([sys.executable, "-m", "aop_toolkit", "compile",
                  "--sop", str(TOOLKIT_HOME / "fixtures/sop/rb-line-001.md"),
                  "--cases", str(TOOLKIT_HOME / "fixtures/cases/fault-management-cases.jsonl"),
                  "--manifest", str(TOOLKIT_HOME / "fixtures/manifests/fault-management.json"),
                  "--version", "v0.1.0", "--out", compiled], cwd=str(TOOLKIT_HOME))
    ok = result.returncode == 0 and os.path.exists(compiled)
    report.append(("compile: SOP + cases + manifest -> AOP document", ok, result.stderr.strip() or result.stdout.strip()))
    if not ok:
        return finish(report)

    # 2. Lint.
    result = run([sys.executable, "-m", "aop_toolkit", "lint", compiled], cwd=str(TOOLKIT_HOME))
    ok = result.returncode == 0
    report.append(("lint: validates against aop-spec schema and clauses", ok, result.stdout.strip()))
    if not ok:
        return finish(report)

    # 3. Publish and resolve.
    registry = Registry(registry_root)
    try:
        entry = registry.publish(compiled)
        resolved = registry.resolve(entry["ref"])
        ok = resolved is not None and resolved["content_digest"] == entry["content_digest"]
        report.append(("registry: publish + resolve with matching content digest", ok, entry["ref"]))
    except Exception as exc:  # noqa: BLE001
        report.append(("registry: publish + resolve with matching content digest", False, str(exc)))
        return finish(report)

    # 4. Provenance chain.
    chain = registry.provenance_chain(entry["ref"], str(TOOLKIT_HOME / "fixtures/cases/fault-management-cases.jsonl"))
    report.append(("registry: provenance chain reaches the observed cases", chain["holds"], json.dumps(chain["derived_from"])))

    # 5. Execute the corpus under the guardrail.
    aop = json.loads(Path(compiled).read_text())
    runtime = Runtime(aop, record_path)
    agent = ScriptedAgent()
    cases = [json.loads(line) for line in (TOOLKIT_HOME / "fixtures/cases/fault-management-cases.jsonl").read_text().splitlines() if line.strip()]
    outcomes = [runtime.run_case(case, agent) for case in cases]
    stats = dict(runtime.stats)
    ok = stats["runs"] == len(cases)
    report.append(("harness: executed %d cases under the guardrail" % len(cases), ok, json.dumps(stats)))

    # 6. The harness's own top-level AOP is itself conformant (SEC-11, F8).
    harness_aop_path = HARNESS_HOME / "aops" / "HR-LINE-001.json"
    result = run([sys.executable, "-m", "aop_toolkit", "lint", str(harness_aop_path)], cwd=str(TOOLKIT_HOME))
    report.append(("harness: its own top-level AOP validates (SEC-11)", result.returncode == 0, result.stdout.strip()))

    # 7. Case record: complete fields, intact chain.
    store = CaseRecordStore(record_path)
    entries = store.read_all()
    incomplete = [e["seq"] for e in entries if any(f not in e for f in MANDATORY_RECORD_FIELDS)]
    report.append(("case record: every entry carries all mandatory fields", not incomplete,
                   "%d entries, %d incomplete" % (len(entries), len(incomplete))))
    intact, problems = store.verify_chain()
    report.append(("case record: append-only chain verifies", intact, "; ".join(problems[:3]) or "chain intact"))

    # 8. Replayability: every dispatched escalation carried a complete bundle.
    bundles_complete = all(
        b.get("triggering_rule") is not None and b.get("context_snapshot", "").startswith("cg://case/")
        for d in runtime.dispatch.log for b in [d["bundle"]]
    )
    report.append(("evidence bundles: complete for every escalation", bundles_complete,
                   "%d escalations dispatched" % len(runtime.dispatch.log)))

    return finish(report)


def finish(report: list[tuple[str, bool, str]]) -> int:
    print("PHASE 4 END-TO-END GATE")
    print("=" * 72)
    passed = True
    for name, ok, detail in report:
        passed = passed and ok
        print("%s  %s" % ("PASS" if ok else "FAIL", name))
        if detail:
            for line in detail.splitlines()[:2]:
                print("      %s" % line)
    print("=" * 72)
    print("GATE %s" % ("PASS" if passed else "FAIL"))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
