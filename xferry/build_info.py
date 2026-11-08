"""Build identity stamped only into isolated distribution build trees."""

from __future__ import annotations

from typing import Literal

BUILD_CHANNEL: Literal["stable", "testing"] = "stable"
SOURCE_COMMIT: str | None = None
BUILD_ID: str | None = None
