"""Canonical SMUGGLE backend components.

The package is deliberately split by responsibility.  ``policy`` owns the
public capability vocabulary, ``request`` validates the HTTP query, the two
renderer modules produce bounded artifacts, and ``store`` owns the one-shot
artifact lifecycle.  The HTTP handler is only a coordinator over those
components.
"""

from .policy import (
    DEFAULT_SMUGGLE_BUILDER,
    DEFAULT_SMUGGLE_POLICY,
    SMUGGLE_ENCRYPTIONS,
    SMUGGLE_MODES,
    SMUGGLE_SCHEMA_VERSION,
    SafeSmuggleBuilderConfig,
    SmugglePolicy,
    SmuggleRequestError,
    SmuggleTempArtifact,
    SmuggleTempPolicy,
    SmuggleTempQuotaExceeded,
    SmuggleTempUsage,
    build_smuggle_capabilities,
)
from .renderer import SmuggleArtifact, render_artifact
from .request import SmuggleRequest, parse_smuggle_query, parse_smuggle_request
from .store import SmuggleArtifactStore, SmuggleTempStore, Store

__all__ = [
    "DEFAULT_SMUGGLE_POLICY",
    "DEFAULT_SMUGGLE_BUILDER",
    "SMUGGLE_ENCRYPTIONS",
    "SMUGGLE_MODES",
    "SMUGGLE_SCHEMA_VERSION",
    "SafeSmuggleBuilderConfig",
    "SmugglePolicy",
    "SmuggleRequestError",
    "SmuggleTempArtifact",
    "SmuggleTempPolicy",
    "SmuggleTempQuotaExceeded",
    "SmuggleTempUsage",
    "build_smuggle_capabilities",
    "SmuggleArtifact",
    "render_artifact",
    "SmuggleRequest",
    "parse_smuggle_query",
    "parse_smuggle_request",
    "SmuggleArtifactStore",
    "SmuggleTempStore",
    "Store",
]
