# Gate Bypass Reconciler

A self-contained Python tool that joins accepted-task events to assignment-gate decision logs and flags any acceptance that bypassed a PASS gate, arrived after a BLOCK or REVIEW decision, or lacks a matching decision entirely.

No external dependencies — runs with the Python standard library.

## What it does

When tasks are assigned through an authorization gate, every acceptance should be backed by a prior PASS decision. This reconciler detects cases where that enforcement broke down:

| Bypass Class | Meaning |
|---|---|
| `matched_pass` | Acceptance has a valid PASS decision within the time window — no issue. |
| `bypass_block` | Acceptance occurred despite a BLOCK decision. |
| `bypass_review` | Acceptance occurred while the gate was still in REVIEW. |
| `missing_decision` | No gate decision exists for this candidate/task pair. |
| `identity_or_window_mismatch` | A decision exists but the acceptance fell outside the 30-minute window. |

## Quick start

```bash
python3 reconciler.py
```

Output includes a human-readable console report followed by deterministic JSON containing:

- `total_acceptances` — number of accepted-task events processed
- `matched_pass_count` — events with a valid PASS
- `bypass_rate` — fraction of acceptances that bypassed enforcement
- `unresolved_count` — events requiring remediation (block, review, or missing)
- `counts_by_bypass_class` — breakdown by classification
- `remediation_queue` — severity-sorted list of flagged events

## How it works

1. **Index gate decisions** by `(task_id, candidate)` with decisions sorted chronologically.
2. **Match each acceptance** to the most recent decision for the same `(task_id, candidate)` pair.
3. **Apply a 30-minute window** — if the decision-to-acceptance gap exceeds 30 minutes, it's flagged as a window mismatch.
4. **Apply a 60-second skew tolerance** — accounts for clock skew or queue delays where a valid PASS might be timestamped slightly after the acceptance event.
5. **Classify and sort** results by severity, with a recommended action per entry.

## Data structures

### Gate Decision

```python
@dataclass(frozen=True)
class GateDecision:
    task_id: str
    candidate_handle_or_wallet: str
    gate_decision: str          # "PASS" | "BLOCK" | "REVIEW"
    decided_at: datetime
```

### Accepted Task Event

```python
@dataclass(frozen=True)
class AcceptedTaskEvent:
    task_id: str
    candidate_handle_or_wallet: str
    acceptance_status: str
    accepted_at: datetime
```

### Remediation Entry

Each flagged event includes:

| Field | Description |
|---|---|
| `event_fingerprint` | SHA-256 truncated hash for deduplication |
| `task_id` | Task identifier |
| `candidate_handle_or_wallet` | Candidate identity |
| `gate_decision` | Matched gate decision (or null) |
| `acceptance_status` | Status of the acceptance event |
| `bypass_class` | Classification of the bypass |
| `decision_age_sec` | Seconds between decision and acceptance |
| `recommended_action` | Suggested remediation step |

## Embedding your own data

Replace the `GATE_DECISIONS` and `ACCEPTED_EVENTS` lists with your own data, or import the `reconcile` and `build_summary` functions directly:

```python
from reconciler import reconcile, build_summary, GateDecision, AcceptedTaskEvent

decisions = [GateDecision(...), ...]
acceptances = [AcceptedTaskEvent(...), ...]

entries = reconcile(decisions, acceptances)
summary = build_summary(entries)
```

## Configuration

| Constant | Default | Purpose |
|---|---|---|
| `WINDOW` | 30 minutes | Maximum allowed gap between decision and acceptance |
| `SKEW_TOLERANCE` | 60 seconds | Buffer for clock skew / queue delay |

## Example output

```
========================================================================
  GATE BYPASS RECONCILER
========================================================================

  Total acceptances : 10
  Matched PASS      : 4
  Bypass rate       : 60.00%
  Unresolved        : 5

  Counts by bypass class:
    matched_pass                       4
    bypass_block                       1
    bypass_review                      2
    missing_decision                   2
    identity_or_window_mismatch        1
```

## License

MIT
