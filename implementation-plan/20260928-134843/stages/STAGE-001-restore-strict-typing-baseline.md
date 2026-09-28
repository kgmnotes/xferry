# STAGE-001 - Restore strict typing baseline

## Status
CLOSED

## Priority
MEDIUM

## Source findings
- `codex-analysis/20260928-131617/project-analysis-report.md` - F-008: pinned mypy fails only at `xferry/handlers/notepad.py:285`.
- `agent-reports/architect-reviewer.md` - lazy Notepad service boundary is a type-confidence issue, not a proven runtime defect.

## Goal
Make `mypy xferry` pass under the pinned strict configuration without changing lazy initialization, locking, or Notepad runtime behavior.

## Non-goals
- Refactor the Notepad domain or handler architecture.
- Change public APIs, JSON shapes, locking semantics, or error behavior.
- Suppress the error with a blanket `Any`, `type: ignore`, or weaker mypy configuration.

## Scope
### Likely files to inspect
- `xferry/handlers/notepad.py` - failing lazy-service accessor.
- `tests/test_handler_context.py` - lazy initialization and concurrency behavior.
- `tests/test_handlers/test_notepad.py` - Notepad behavior regression coverage.
- `pyproject.toml` - strict mypy contract.

### Likely files to change
- `xferry/handlers/notepad.py` - add explicit, behavior-preserving type narrowing or a typed attribute.
- `tests/test_handler_context.py` - only if a focused regression assertion is needed.

### Files that must not be changed
- `pyproject.toml` - do not weaken strict typing.
- `xferry/server.py` and `xferry/request_pipeline.py` - unrelated composition/runtime paths.
- `.github/workflows/*` - CI should become green through the code fix.

## Dependencies
- Depends on: `None`
- Blocks: STAGE-003

## Implementation steps
1. Reproduce the exact pinned mypy error and identify why the `getattr` result remains `Any`.
2. Add the smallest explicit typed state/narrowing that preserves double-checked lazy creation and the existing lock.
3. Run focused concurrency and handler tests, then strict mypy and Ruff.
4. Confirm the diff contains no configuration suppression or unrelated refactor.

## Acceptance criteria
- [ ] Pinned `mypy xferry` exits successfully with strict settings unchanged.
- [ ] Lazy Notepad service creation remains single-instance under concurrent access.
- [ ] Existing Notepad behavior and handler-context tests pass.
- [ ] No `type: ignore`, `cast(Any, ...)`, or weakened typing rule is introduced for this path.

## Verification plan
| Check | Command or method | Expected result |
|---|---|---|
| Targeted tests | `python -m pytest -q tests/test_handler_context.py tests/test_handlers/test_notepad.py` | All pass |
| Type/lint/build | `mypy xferry && ruff check xferry/handlers/notepad.py tests/test_handler_context.py && ruff format --check xferry/handlers/notepad.py tests/test_handler_context.py` | Clean |
| Manual/static review | Inspect `_get_notepad_service()` and the lock path | Runtime ordering and lazy behavior unchanged |

## Suggested subagents
- `python-pro` - propose strict, behavior-preserving narrowing.
- `test-automator` - review concurrency regression coverage if a test is added.
- `reviewer` - verify no typing suppression or behavioral drift.

## Risks and rollback
- Risk: eager initialization or incorrect attribute typing changes concurrency/lifecycle behavior.
- Rollback: revert the local accessor/test change; no state or data migration is involved.

## Completion notes
- Closed: 2026-09-28 14:43:22 +0300.
- Added an explicit `NotepadService | None` annotation to the existing lazy-service local without changing attribute lookup, double-checked locking, construction, or assignment order.
- Pinned strict mypy, 130 focused tests, scoped Ruff checks, and the 3,171-test full suite pass.
- Independent read-only Python review confirmed the one-line change introduces no typing suppression or behavioral drift.
- Report: `../stage-reports/STAGE-001-20260928-143829.md`.
