#!/usr/bin/env python3
"""Accepted-Task Gate Bypass Reconciler.

Joins sanitized accepted-task events to assignment-gate decision logs and
flags any acceptance that bypassed PASS, arrived after BLOCK or REVIEW, or
lacks a matching decision within a bounded window.

Self-contained – no external files required.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, List


@dataclass(frozen=True)
class GateDecision:
    task_id: str
    candidate_handle_or_wallet: str
    gate_decision: str
    decided_at: datetime


@dataclass(frozen=True)
class AcceptedTaskEvent:
    task_id: str
    candidate_handle_or_wallet: str
    acceptance_status: str
    accepted_at: datetime


@dataclass
class RemediationEntry:
    event_fingerprint: str
    task_id: str
    candidate_handle_or_wallet: str
    gate_decision: str | None
    acceptance_status: str
    bypass_class: str
    decision_age_sec: float | None
    recommended_action: str


WINDOW = timedelta(minutes=30)
SKEW_TOLERANCE = timedelta(seconds=60)

BYPASS_CLASSES = (
    "matched_pass",
    "bypass_block",
    "bypass_review",
    "missing_decision",
    "identity_or_window_mismatch",
)

ACTIONS: Dict[str, str] = {
    "matched_pass": "no_action",
    "bypass_block": "revoke_and_investigate",
    "bypass_review": "escalate_for_manual_review",
    "missing_decision": "request_gate_decision",
    "identity_or_window_mismatch": "verify_identity_and_window",
}


def _fingerprint(task_id: str, candidate: str, accepted_at: datetime) -> str:
    raw = f"{task_id}|{candidate}|{accepted_at.isoformat()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _t(minutes: int) -> datetime:
    return datetime(2026, 4, 13, 10, 0, 0, tzinfo=timezone.utc) + timedelta(minutes=minutes)


GATE_DECISIONS: List[GateDecision] = [
    GateDecision("T001", "candidate_a", "PASS",   _t(0)),
    GateDecision("T002", "candidate_b", "BLOCK",  _t(5)),
    GateDecision("T003", "candidate_c", "REVIEW", _t(10)),
    GateDecision("T004", "candidate_d", "PASS",   _t(0)),
    GateDecision("T005", "candidate_e", "BLOCK",  _t(2)),
    GateDecision("T005", "candidate_e", "PASS",   _t(8)),
    GateDecision("T006", "candidate_f", "PASS",   _t(1)),
    GateDecision("T007", "candidate_g", "PASS",   _t(3)),
    GateDecision("T008", "candidate_h", "BLOCK",  _t(4)),
    GateDecision("T009", "candidate_i", "REVIEW", _t(6)),
    GateDecision("T010", "candidate_j", "PASS",   _t(7)),
]

ACCEPTED_EVENTS: List[AcceptedTaskEvent] = [
    AcceptedTaskEvent("T001", "candidate_a",      "accepted", _t(10)),
    AcceptedTaskEvent("T002", "candidate_b",      "accepted", _t(15)),
    AcceptedTaskEvent("T003", "candidate_c",      "accepted", _t(20)),
    AcceptedTaskEvent("T004", "candidate_d",      "accepted", _t(45)),
    AcceptedTaskEvent("T005", "candidate_e",      "accepted", _t(18)),
    AcceptedTaskEvent("T006", "candidate_f_alt",  "accepted", _t(5)),
    AcceptedTaskEvent("T007", "candidate_g",      "accepted", _t(12)),
    AcceptedTaskEvent("T099", "candidate_x",      "accepted", _t(22)),
    AcceptedTaskEvent("T009", "candidate_i",      "accepted", _t(25)),
    AcceptedTaskEvent("T010", "candidate_j",      "accepted", _t(14)),
]


def reconcile(
    decisions: List[GateDecision],
    acceptances: List[AcceptedTaskEvent],
    window: timedelta = WINDOW,
) -> List[RemediationEntry]:
    idx: Dict[tuple, List[GateDecision]] = {}
    for d in sorted(decisions, key=lambda d: d.decided_at):
        idx.setdefault((d.task_id, d.candidate_handle_or_wallet), []).append(d)

    results: List[RemediationEntry] = []

    for acc in acceptances:
        key = (acc.task_id, acc.candidate_handle_or_wallet)
        candidates = idx.get(key)

        if not candidates:
            results.append(RemediationEntry(
                event_fingerprint=_fingerprint(acc.task_id, acc.candidate_handle_or_wallet, acc.accepted_at),
                task_id=acc.task_id,
                candidate_handle_or_wallet=acc.candidate_handle_or_wallet,
                gate_decision=None,
                acceptance_status=acc.acceptance_status,
                bypass_class="missing_decision",
                decision_age_sec=None,
                recommended_action=ACTIONS["missing_decision"],
            ))
            continue

        matched: GateDecision | None = None
        for d in reversed(candidates):
            if d.decided_at <= acc.accepted_at + SKEW_TOLERANCE:
                matched = d
                break

        if matched is None:
            results.append(RemediationEntry(
                event_fingerprint=_fingerprint(acc.task_id, acc.candidate_handle_or_wallet, acc.accepted_at),
                task_id=acc.task_id,
                candidate_handle_or_wallet=acc.candidate_handle_or_wallet,
                gate_decision=candidates[0].gate_decision,
                acceptance_status=acc.acceptance_status,
                bypass_class="identity_or_window_mismatch",
                decision_age_sec=(acc.accepted_at - candidates[0].decided_at).total_seconds(),
                recommended_action=ACTIONS["identity_or_window_mismatch"],
            ))
            continue

        age = (acc.accepted_at - matched.decided_at).total_seconds()
        reported_age = max(age, 0.0)

        if age < 0:
            bypass_class = (
                "matched_pass" if matched.gate_decision == "PASS"
                else f"skew_tolerance_{matched.gate_decision.lower()}"
            )
        elif age > window.total_seconds():
            bypass_class = "identity_or_window_mismatch"
        elif matched.gate_decision == "PASS":
            bypass_class = "matched_pass"
        elif matched.gate_decision == "BLOCK":
            bypass_class = "bypass_block"
        elif matched.gate_decision == "REVIEW":
            bypass_class = "bypass_review"
        else:
            bypass_class = "identity_or_window_mismatch"

        results.append(RemediationEntry(
            event_fingerprint=_fingerprint(acc.task_id, acc.candidate_handle_or_wallet, acc.accepted_at),
            task_id=acc.task_id,
            candidate_handle_or_wallet=acc.candidate_handle_or_wallet,
            gate_decision=matched.gate_decision,
            acceptance_status=acc.acceptance_status,
            bypass_class=bypass_class,
            decision_age_sec=reported_age,
            recommended_action=ACTIONS.get(bypass_class, ACTIONS["identity_or_window_mismatch"]),
        ))

    results.sort(
        key=lambda r: (
            BYPASS_CLASSES.index(r.bypass_class) if r.bypass_class in BYPASS_CLASSES else 99,
            r.task_id,
        )
    )
    return results


def build_summary(entries: List[RemediationEntry]) -> dict:
    total = len(entries)
    bypass_count = sum(1 for e in entries if e.bypass_class != "matched_pass")
    matched_pass_count = sum(1 for e in entries if e.bypass_class == "matched_pass")
    unresolved_count = sum(
        1 for e in entries
        if e.bypass_class in ("bypass_block", "bypass_review", "missing_decision")
    )

    by_class: Dict[str, int] = {}
    for e in entries:
        by_class[e.bypass_class] = by_class.get(e.bypass_class, 0) + 1

    bypass_rate = round(bypass_count / total, 4) if total else 0.0

    return {
        "total_acceptances": total,
        "matched_pass_count": matched_pass_count,
        "bypass_rate": bypass_rate,
        "unresolved_count": unresolved_count,
        "counts_by_bypass_class": by_class,
        "remediation_queue": [asdict(e) for e in entries],
    }


def main() -> None:
    entries = reconcile(GATE_DECISIONS, ACCEPTED_EVENTS)
    summary = build_summary(entries)

    print("=" * 72)
    print("  GATE BYPASS RECONCILER")
    print("=" * 72)

    print(f"\n  Total acceptances : {summary['total_acceptances']}")
    print(f"  Matched PASS      : {summary['matched_pass_count']}")
    print(f"  Bypass rate       : {summary['bypass_rate']:.2%}")
    print(f"  Unresolved        : {summary['unresolved_count']}")

    print("\n  Counts by bypass class:")
    for cls in BYPASS_CLASSES:
        cnt = summary["counts_by_bypass_class"].get(cls, 0)
        if cnt:
            print(f"    {cls:30s} {cnt}")

    print("\n  Remediation queue (severity-sorted):")
    print("-" * 72)
    for e in summary["remediation_queue"]:
        age_val = e["decision_age_sec"]
        age_str = "   N/A" if age_val is None else f"{age_val:.0f}s".rjust(6)
        print(
            f"  {e['event_fingerprint']}  {e['task_id']:5s}  "
            f"{e['candidate_handle_or_wallet']:20s}  "
            f"gate={str(e['gate_decision']):6s}  "
            f"class={e['bypass_class']:28s}  "
            f"age={age_str}  "
            f"action={e['recommended_action']}"
        )
    print("-" * 72)

    print("\n  Deterministic JSON output:")
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
