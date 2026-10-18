"""
gate.py
-------
The ONLY path from an agent to a tool.

For every call the gate:
  1. labels every argument itself from the Catalogue (the agent cannot
     claim its own provenance),
  2. read-only tools -> ALLOW; risky tools -> rules R1-R4,
  3. ALLOW -> runs the tool now; HOLD -> parks it, the world is unchanged,
  4. writes a signed record of the decision to the proof log (if given).

What the AGENT sees on HOLD is only "HELD for human review (REQ-xxx)".
Reasons go to the reviewer queue and the proof log, never to the agent,
so a manipulated agent cannot probe the rules.

Rule IDs: "OK" = allowed; "R0" = unknown tool (held); "R1".."R4" = rule hits.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from provgate.provenance import Catalogue, default_catalogue
from provgate.rules import RULES, POLICY_VERSION, Reason
from provgate.world_tools import World, READ_ONLY, RISKY

ALLOW, HOLD = "ALLOW", "HOLD"
APPROVE, REJECT = "APPROVE", "REJECT"


@dataclass
class Decision:
    request_id: str
    tool: str
    args: dict                      # {arg: {"value": v, "source": label, "trust": t}}
    decision: str                   # ALLOW | HOLD
    reasons: list = field(default_factory=list)   # [Reason] -- reviewer/log only
    raw_args: dict = field(default_factory=dict)
    result: str | None = None       # tool output if it ran
    policy: str = POLICY_VERSION

    @property
    def agent_message(self) -> str:
        """The ONLY thing returned to the agent."""
        return self.result if self.decision == ALLOW else f"HELD for human review ({self.request_id})"

    def record(self) -> dict:
        return {"request_id": self.request_id, "tool": self.tool, "args": self.args,
                "decision": self.decision, "rules": [r.rule for r in self.reasons],
                "reasons": [r.text for r in self.reasons], "policy": self.policy}


class Gate:
    def __init__(self, world: World, catalogue: Catalogue | None = None, log=None, agent_id="ap-assistant"):
        self.world = world
        self.catalogue = catalogue or default_catalogue()
        self.log = log
        self.agent_id = agent_id
        self.pending: dict[str, Decision] = {}
        self._n = 0
        self.stats = {"actions": 0, "allowed": 0, "held": 0, "approved": 0, "rejected": 0}

    def _log(self, rtype, payload):
        if self.log is not None:
            self.log.append(rtype, payload)

    def label_args(self, args: dict) -> dict:
        return {k: (v, self.catalogue.label(v)) for k, v in args.items()}

    def call(self, tool: str, args: dict) -> Decision:
        self._n += 1
        rid = f"REQ-{self._n:03d}"
        labelled = self.label_args(args)
        shown = {k: {"value": v, "source": s.label, "trust": s.trust} for k, (v, s) in labelled.items()}

        if tool in READ_ONLY:
            d = Decision(rid, tool, shown, ALLOW, [Reason("OK", "OK: read-only tool")])
        elif tool in RISKY:
            reasons = [r for rule in RULES for r in rule(tool, labelled, self.world)]
            if reasons:
                d = Decision(rid, tool, shown, HOLD, reasons)
            else:
                d = Decision(rid, tool, shown, ALLOW,
                             [Reason("OK", "OK: all arguments trusted; R1-R4 passed")])
        else:
            d = Decision(rid, tool, shown, HOLD, [Reason("R0", f"R0: unknown tool '{tool}'")])
        d.raw_args = dict(args)

        self.stats["actions"] += 1
        self.stats["allowed" if d.decision == ALLOW else "held"] += 1
        self._log("decision", {"agent": self.agent_id, **d.record()})
        if d.decision == ALLOW:
            d.result = self.world.dispatch(tool, args)
            if tool in RISKY:
                self._log("executed", {"request_id": rid, "tool": tool, "result": d.result})
        else:
            self.pending[rid] = d
        return d

    # ---- reviewer side ------------------------------------------------------
    def queue(self) -> list[Decision]:
        """Held calls WITH full reasons -- for the human reviewer only."""
        return list(self.pending.values())

    def review(self, request_id: str, reviewer: str, decision: str, note: str) -> str:
        if decision not in (APPROVE, REJECT):
            raise ValueError("decision must be APPROVE or REJECT")
        if not reviewer.strip() or not note.strip():
            raise ValueError("reviewer and note are required")
        d = self.pending.pop(request_id)
        # Self-contained record: labels, rule IDs, reasons, reviewer, decision.
        self._log("review", {**d.record(),
                             "reviewer": reviewer, "review_decision": decision, "note": note})
        self.stats["approved" if decision == APPROVE else "rejected"] += 1
        if decision == APPROVE:
            d.result = self.world.dispatch(d.tool, d.raw_args)
            self._log("executed", {"request_id": request_id, "tool": d.tool, "result": d.result})
            return d.result
        return f"Rejected by {reviewer}: not executed."
