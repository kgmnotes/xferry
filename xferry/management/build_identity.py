"""Bind opt-in testing consumers to the exact CLI build they installed."""

from __future__ import annotations

from .release_contract import ReleaseManifest, require_build_id, require_source_commit


def testing_identity(version: str) -> dict[str, str]:
    from xferry import build_info, config

    if build_info.BUILD_CHANNEL != "testing" or config.__version__ != version:
        raise ValueError(
            "Install the exact testing CLI wheel for this version before setup or update."
        )
    try:
        source = require_source_commit(build_info.SOURCE_COMMIT)
        build = require_build_id(build_info.BUILD_ID)
    except ValueError:
        raise ValueError(
            "Testing CLI build identity is missing or invalid; reinstall its wheel."
        ) from None
    return {"channel": "testing", "source_commit": source, "build_id": build}


def verify_testing_identity(manifest: ReleaseManifest, version: str) -> dict[str, str]:
    identity = testing_identity(version)
    if (
        manifest.version != version
        or manifest.channel != "testing"
        or manifest.source_commit != identity["source_commit"]
        or manifest.build_id != identity["build_id"]
    ):
        raise ValueError("Testing runtime and installed CLI do not belong to the same build.")
    return identity
