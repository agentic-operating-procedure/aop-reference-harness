"""The scripted reference agent.

The least authoritative and most replaceable part of the estate. This agent
proposes the variant's steps in order from the case context it is handed, and
nothing else: it holds no authority, makes no judgement, and cannot influence
the guardrail that governs it (the governing principle, and the test of
ARC-3: replace the agent without touching the AOP).
"""

from __future__ import annotations


class ScriptedAgent:
    def __init__(self, name: str = "scripted-reference-agent"):
        self.name = name

    def propose(self, variant_steps: list[str], context: dict) -> list[str]:
        """Propose the planned actions. A model-driven agent replaces this
        method; the runtime, guardrail and record do not change."""
        return list(variant_steps)
