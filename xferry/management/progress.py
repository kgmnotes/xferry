"""Optional, presentation-only notifications for management operations."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from functools import wraps
from typing import Literal, ParamSpec, TypeVar


@dataclass(frozen=True, slots=True)
class ProgressEvent:
    """A fixed stage identifier and its observed completion state, without payloads."""

    stage: str
    state: Literal["running", "done", "failed"]


ProgressObserver = Callable[[ProgressEvent], None]
_observer: ContextVar[ProgressObserver | None] = ContextVar("xferry_progress", default=None)
_P = ParamSpec("_P")
_T = TypeVar("_T")


@contextmanager
def observe_progress(observer: ProgressObserver | None) -> Iterator[None]:
    """Scope an observer to this operation, inheriting it for nested adapters."""
    if observer is None:
        yield
        return
    token = _observer.set(observer)
    try:
        yield
    finally:
        _observer.reset(token)


def with_progress(method: Callable[_P, _T]) -> Callable[_P, _T]:
    """Bind a component's current observer without changing adapter call contracts."""

    @wraps(method)
    def call(*args: _P.args, **kwargs: _P.kwargs) -> _T:
        observer = getattr(args[0], "progress", None) if args else None
        with observe_progress(observer):
            return method(*args, **kwargs)

    return call


def emit_progress(stage: str, state: Literal["running", "done", "failed"]) -> None:
    observer = _observer.get()
    if observer is not None:
        try:
            observer(ProgressEvent(stage, state))
        except Exception:
            # A broken terminal is not a management failure or a reason to roll back.
            pass


@contextmanager
def progress_stage(stage: str) -> Iterator[None]:
    """Report a stage whose failures are expressed by an exception."""
    emit_progress(stage, "running")
    try:
        yield
    except BaseException:
        emit_progress(stage, "failed")
        raise
    else:
        emit_progress(stage, "done")


def run_stage(
    stage: str,
    operation: Callable[[], _T],
    *,
    ok: Callable[[_T], bool] | None = None,
) -> _T:
    """Report a real blocking operation, including unsuccessful returned results."""
    emit_progress(stage, "running")
    try:
        result = operation()
    except BaseException:
        emit_progress(stage, "failed")
        raise
    emit_progress(stage, "done" if ok is None or ok(result) else "failed")
    return result
