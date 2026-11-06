"""Explicit artifact origins and trust policy for stable and testing installs."""

from __future__ import annotations

import hashlib
import json
import re
from typing import TYPE_CHECKING, Literal, cast
from urllib.parse import urlsplit

from .versions import (
    SUPPORTED_RELEASE_MAJOR,
    is_canonical_release_version,
    is_testing_version,
)

if TYPE_CHECKING:
    from .release_contract import ReleaseManifest
    from .release_trust import ReleaseKeyRing

Channel = Literal["stable", "testing"]
DEFAULT_RELEASE_BASE_URL = "https://github.com/kgmnotes/xferry/releases"
STABLE_IMAGE = "ghcr.io/kgmnotes/xferry"
TESTING_IMAGE = "ghcr.io/kgmnotes/xferry-testing"
TESTING_IMAGES_NAME = "testing-images.json"
MAX_TESTING_IMAGES_BYTES = 16 * 1024


def normalize_channel(value: object) -> Channel:
    if not isinstance(value, str) or value not in {"stable", "testing"}:
        raise ValueError("channel must be stable or testing")
    return cast(Channel, value)


def validate_version_for_channel(value: object, channel: Channel = "stable") -> str:
    """Reject implicit channel changes and versions outside the supported major."""
    selected = normalize_channel(channel)
    valid = (
        is_testing_version(value) if selected == "testing" else is_canonical_release_version(value)
    )
    if not valid or not isinstance(value, str) or value.split(".", 1)[0] != SUPPORTED_RELEASE_MAJOR:
        raise ValueError(f"an exact supported {selected} version is required")
    return value


def release_tag(version: str, channel: Channel = "stable") -> str:
    selected = normalize_channel(channel)
    validated = validate_version_for_channel(version, selected)
    return f"testing-v{validated}" if selected == "testing" else f"v{validated}"


def manifest_url(
    version: str,
    platform: str,
    channel: Channel = "stable",
    base_url: str = DEFAULT_RELEASE_BASE_URL,
) -> str:
    from .release_contract import release_manifest_asset_name, require_platform_id

    location = urlsplit(base_url)
    if location.scheme != "https" or not location.netloc or location.query or location.fragment:
        raise ValueError("release source must be an HTTPS base URL")
    selected_platform = require_platform_id(platform)
    name = release_manifest_asset_name(selected_platform)
    return f"{base_url.rstrip('/')}/download/{release_tag(version, channel)}/{name}"


def image_reference(version: str, channel: Channel = "stable") -> str:
    selected = normalize_channel(channel)
    validated = validate_version_for_channel(version, selected)
    repository = TESTING_IMAGE if selected == "testing" else STABLE_IMAGE
    return f"{repository}:v{validated}"


def key_ring_for_channel(channel: Channel = "stable") -> ReleaseKeyRing:
    from .release_trust import DEFAULT_RELEASE_KEY_RING, DEFAULT_TESTING_KEY_RING

    return (
        DEFAULT_TESTING_KEY_RING
        if normalize_channel(channel) == "testing"
        else DEFAULT_RELEASE_KEY_RING
    )


def parse_testing_images(payload: bytes, manifest: ReleaseManifest) -> str:
    """Bind the immutable Docker image to already authenticated native build metadata."""

    def unique_keys(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    try:
        if (
            manifest.schema_version != 3
            or manifest.channel != "testing"
            or not isinstance(payload, bytes)
            or not 0 < len(payload) <= MAX_TESTING_IMAGES_BYTES
            or dict(manifest.artifact_digests).get(TESTING_IMAGES_NAME)
            != hashlib.sha256(payload).hexdigest()
        ):
            raise ValueError
        document = json.loads(payload.decode("utf-8"), object_pairs_hook=unique_keys)
        if not isinstance(document, dict) or set(document) != {
            "schema",
            "channel",
            "version",
            "source_commit",
            "build_id",
            "image",
        }:
            raise ValueError
        image = document["image"]
        if (
            type(document["schema"]) is not int
            or document["schema"] != 1
            or document["channel"] != "testing"
            or document["version"] != manifest.version
            or document["source_commit"] != manifest.source_commit
            or document["build_id"] != manifest.build_id
            or not isinstance(image, str)
            or re.fullmatch(re.escape(TESTING_IMAGE) + r"@sha256:[0-9a-f]{64}", image) is None
        ):
            raise ValueError
        canonical = {
            "schema": 1,
            "channel": "testing",
            "version": manifest.version,
            "source_commit": manifest.source_commit,
            "build_id": manifest.build_id,
            "image": image,
        }
        if (json.dumps(canonical, indent=2) + "\n").encode("utf-8") != payload:
            raise ValueError
        return image
    except (UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError):
        raise ValueError("invalid testing image catalog") from None
