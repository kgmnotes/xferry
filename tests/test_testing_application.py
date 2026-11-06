"""Preview consumers bind the explicit channel to one authenticated CLI build."""

from __future__ import annotations

import hashlib
import io
import json
import urllib.request
from argparse import Namespace
from dataclasses import replace
from http.client import HTTPMessage
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tests.test_management_setup import (
    FakeRunner,
    _executor,
    _ok_preflight,
    _plan,
    _seed_release,
)
from xferry import build_info, config
from xferry.management import application, artifact_download, cli, release_verifier
from xferry.management.build_identity import testing_identity as installed_testing_identity
from xferry.management.build_identity import verify_testing_identity
from xferry.management.deployment import DeploymentSpec, OperationResult
from xferry.management.health import _parse_health_response
from xferry.management.instances import Instance
from xferry.management.release_contract import ReleaseManifest, artifact_name
from xferry.management.release_trust import (
    TESTING_MANIFEST_SIGNATURE_TYPE,
    ReleaseKeyRing,
    TrustedReleaseKey,
    create_detached_signature,
)

VERSION = "0.5.1.dev123001"
SOURCE = "a" * 40
BUILD = "123.1"
IDENTITY = {"channel": "testing", "source_commit": SOURCE, "build_id": BUILD}


@pytest.fixture
def testing_wheel(monkeypatch):
    monkeypatch.setattr(build_info, "BUILD_CHANNEL", "testing")
    monkeypatch.setattr(build_info, "SOURCE_COMMIT", SOURCE)
    monkeypatch.setattr(build_info, "BUILD_ID", BUILD)
    monkeypatch.setattr(config, "__version__", VERSION)


def _manifest(payload=b"testing executable", **overrides):
    options = {
        "version": VERSION,
        "platform": "linux-x86_64",
        "executable_size": len(payload),
        "executable_sha256": hashlib.sha256(payload).hexdigest(),
        "source_commit": SOURCE,
        "workflow_run": "123",
        "build_id": BUILD,
        "artifact_digests": {
            artifact_name(VERSION, "linux-x86_64"): hashlib.sha256(payload).hexdigest()
        },
        "signing_key_ids": ("testing-unit",),
    }
    options.update(overrides)
    return ReleaseManifest.create_v3(**options)


def _instance(tmp_path, channel="stable", backend="native"):
    profile = tmp_path / "profile.ini"
    profile.write_text("[server]\nconfig_version = 1\naccess = private\n")
    spec = DeploymentSpec.new(
        backend,
        profile,
        tmp_path / "files",
        tmp_path / "state",
        {
            "channel": channel,
            "version": VERSION if channel == "testing" else "0.5.0",
            **(
                {"sha256": "a" * 64}
                if backend == "native"
                else {
                    "image": "ghcr.io/kgmnotes/xferry@sha256:" + "a" * 64,
                }
            ),
            **(IDENTITY if channel == "testing" else {}),
        },
        backend_options={"project": "xferry-test"} if backend == "docker" else {},
    )
    manifest = tmp_path / "deployment.json"
    manifest.write_text(json.dumps(spec.to_json()))
    return Instance(spec.instance_id, backend, profile, manifest)


def test_testing_identity_uses_exact_installed_wheel(testing_wheel):
    assert installed_testing_identity(VERSION) == IDENTITY
    assert verify_testing_identity(_manifest(), VERSION) == IDENTITY


@pytest.mark.parametrize("channel,version", [("stable", VERSION), ("testing", "0.5.1.dev999001")])
def test_testing_identity_rejects_stable_or_different_cli(
    testing_wheel, monkeypatch, channel, version
):
    monkeypatch.setattr(build_info, "BUILD_CHANNEL", channel)
    with pytest.raises(ValueError, match="exact testing CLI wheel"):
        installed_testing_identity(version)


@pytest.mark.parametrize(
    "field,value",
    [("SOURCE_COMMIT", None), ("SOURCE_COMMIT", "bad"), ("BUILD_ID", None), ("BUILD_ID", "123.0")],
)
def test_testing_identity_rejects_missing_or_invalid_build_metadata(
    testing_wheel, monkeypatch, field, value
):
    monkeypatch.setattr(build_info, field, value)
    with pytest.raises(ValueError, match="build identity is missing or invalid"):
        installed_testing_identity(VERSION)


@pytest.mark.parametrize(
    "override",
    [
        {"version": "0.5.1.dev123002"},
        {"channel": "stable"},
        {"source_commit": "b" * 40},
        {"build_id": "123.2"},
    ],
)
def test_runtime_must_match_wheel_version_channel_source_and_attempt(testing_wheel, override):
    with pytest.raises(ValueError, match="same build"):
        verify_testing_identity(replace(_manifest(), **override), VERSION)


@pytest.mark.parametrize("backend", ["native", "docker"])
def test_testing_setup_rejects_stable_cli_before_host_or_network_work(backend):
    with pytest.raises(ValueError, match="exact testing CLI wheel"):
        application.ManagementApplication().setup(
            backend=backend, channel="testing", version=VERSION, dry_run=True
        )


def test_cli_setup_requires_explicit_testing_channel(monkeypatch, capsys):
    monkeypatch.setattr(
        application, "default_application", lambda: pytest.fail("must not dispatch")
    )
    assert cli.main(["setup", "--to", VERSION, "--dry-run"]) == 2
    assert "exact supported release version" in capsys.readouterr().err


@pytest.mark.parametrize("backend", ["native", "docker"])
def test_cli_setup_forwards_testing_opt_in_and_exact_version(monkeypatch, backend):
    calls = []
    app = SimpleNamespace(
        setup=lambda **options: calls.append(options) or OperationResult(0, "preview")
    )
    monkeypatch.setattr(application, "default_application", lambda: app)
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False)
    assert (
        cli.main(
            [
                "setup",
                "--backend",
                backend,
                "--channel",
                "testing",
                "--to",
                VERSION,
                "--access",
                "private",
                "--dry-run",
            ]
        )
        == 0
    )
    assert calls[0]["channel"] == "testing"
    assert calls[0]["version"] == VERSION
    assert calls[0]["dry_run"] is True


def test_reviewed_setup_preserves_testing_identity_through_privilege_escalation():
    assert cli._setup_arguments(Namespace(channel="testing", to=VERSION, dry_run=True)) == [
        "setup",
        "--to",
        VERSION,
        "--channel",
        "testing",
        "--dry-run",
    ]


@pytest.mark.parametrize("action", ["update", "rollback"])
def test_native_testing_lifecycle_rejects_stable_cli_before_backend(tmp_path, action):
    selected = _instance(tmp_path, "testing")
    adapter = SimpleNamespace(operate=lambda *_args, **_kwargs: pytest.fail("backend must not run"))
    app = application.ManagementApplication(native_backend=adapter)
    with pytest.raises(ValueError, match="exact testing CLI wheel"):
        app.operate(action, selected, version=VERSION, dry_run=True)


@pytest.mark.parametrize("action", ["update", "rollback"])
@pytest.mark.parametrize("recorded", ["stable", "testing"])
def test_native_testing_lifecycle_binds_backend_to_cli_build(
    testing_wheel, tmp_path, action, recorded
):
    selected = _instance(tmp_path, recorded)
    calls = []
    adapter = SimpleNamespace(
        operate=lambda *args, **kwargs: (
            calls.append((args, kwargs)) or OperationResult(0, "preview")
        )
    )
    app = application.ManagementApplication(native_backend=adapter)
    # Entering testing is explicit. Once recorded, the channel is inferred.
    options = {"channel": "testing"} if recorded == "stable" else {}
    if action == "update":
        options["version"] = VERSION
    assert app.operate(action, selected, dry_run=True, **options).exit_code == 0
    assert calls == [
        (
            (action, selected),
            {
                "dry_run": True,
                "version": VERSION,
                "channel": "testing",
                "expected_source_commit": SOURCE,
                "expected_build_id": BUILD,
            },
        )
    ]


@pytest.mark.parametrize("recorded,requested", [("stable", "testing"), ("testing", "stable")])
def test_setup_cannot_silently_switch_existing_channel(
    testing_wheel, tmp_path, recorded, requested
):
    selected = _instance(tmp_path, recorded, "docker")
    adapter = SimpleNamespace(setup=lambda *_args, **_kwargs: pytest.fail("setup must not run"))
    app = application.ManagementApplication(compose_backend=adapter)
    with pytest.raises(ValueError, match="update with an explicit --channel"):
        app.setup(
            backend="docker",
            instance_id=selected,
            channel=requested,
            version=VERSION if requested == "testing" else "0.5.1",
        )


@pytest.mark.parametrize("dry_run", [False, True])
@pytest.mark.parametrize("requested", ["stable", "testing"])
def test_setup_rejects_another_runtime_channel_before_preflight_or_bootstrap(
    testing_wheel, tmp_path, monkeypatch, dry_run, requested
):
    plan = _plan(tmp_path)
    installed = _seed_release(plan.layout, "0.5.0", current=True)
    if requested == "stable":
        preview = installed.with_name(VERSION)
        installed.rename(preview)
        (preview / "xferry").write_bytes(b"testing executable")
        (preview / "xferry-release.json").write_bytes(_manifest().to_bytes())
        current = plan.layout.release_root / "current"
        current.unlink()
        current.symlink_to("releases/" + VERSION)
    from xferry.management.managed_state import has_unsupported_managed_state

    assert not has_unsupported_managed_state(plan.layout)
    assert not (plan.layout.config_file.parent / "deployment.json").exists()
    runner = FakeRunner()
    app = application.ManagementApplication(
        runner=runner, layout=plan.layout, effective_uid=lambda: 0
    )
    monkeypatch.setattr(
        "xferry.management.platform.detect_host_facts",
        lambda **_kwargs: pytest.fail("channel mismatch must precede host preflight"),
    )
    monkeypatch.setattr(
        "xferry.management.bootstrap.install_release",
        lambda *_args, **_kwargs: pytest.fail("channel mismatch must precede bootstrap"),
    )
    before = plan.layout.current_executable.read_bytes()
    with pytest.raises(ValueError, match="another channel"):
        app.setup(
            channel=requested,
            version=VERSION if requested == "testing" else "0.5.1",
            dry_run=dry_run,
            access="private",
        )
    assert runner.commands == []
    assert plan.layout.current_executable.read_bytes() == before
    assert not plan.layout.data_root.exists()


@pytest.mark.parametrize("dry_run", [False, True])
def test_retained_testing_setup_cannot_resume_under_implicit_stable_channel(
    tmp_path, monkeypatch, dry_run
):
    plan = _plan(tmp_path)
    selected = _instance(tmp_path, "testing")
    app = application.ManagementApplication(layout=plan.layout, effective_uid=lambda: 0)
    monkeypatch.setattr(app, "resolve", lambda _path: selected)
    monkeypatch.setattr(
        "xferry.management.managed_state.has_unsupported_managed_state", lambda _layout: False
    )
    monkeypatch.setattr("xferry.management.managed_state.has_retained_state", lambda _layout: True)
    monkeypatch.setattr(
        "xferry.management.bootstrap.install_release",
        lambda *_args, **_kwargs: pytest.fail("retained channel mismatch must precede bootstrap"),
    )
    with pytest.raises(ValueError, match="retained channel"):
        app.setup(version="0.5.1", dry_run=dry_run, access="private")


def test_retained_resume_preserves_testing_build_metadata(tmp_path):
    from tests.test_backend_lifecycle import native
    from xferry.management.deployment import write_manifest
    from xferry.management.managed_state import RETAINED_STATE_CONTENT, retained_state_path

    _app, instance, _runner, layout = native(tmp_path)
    original = layout.current_executable.resolve(strict=True).parent
    preview = original.with_name(VERSION)
    original.rename(preview)
    (preview / "xferry").write_bytes(b"testing executable")
    (preview / "xferry-release.json").write_bytes(_manifest().to_bytes())
    current = layout.release_root / "current"
    current.unlink()
    current.symlink_to("releases/" + VERSION)
    artifact = {**IDENTITY, "version": VERSION, "sha256": _manifest().executable_sha256}
    write_manifest(instance.manifest, replace(instance.spec, artifact=artifact))
    layout.unit_file.unlink()
    retained_state_path(layout).write_bytes(RETAINED_STATE_CONTENT)
    retained_state_path(layout).chmod(0o600)
    credentials = layout.auth_file.read_bytes()
    runner = FakeRunner(service_present=False)

    result = _executor(tmp_path, runner).resume(layout)

    assert result.exit_code == 0, result.message
    assert instance.spec.artifact == artifact
    assert layout.auth_file.read_bytes() == credentials
    assert runner.active and runner.enabled
    assert not retained_state_path(layout).exists()


def test_native_testing_setup_binds_bootstrap_and_records_verified_identity(
    testing_wheel, tmp_path, monkeypatch
):
    from xferry.management.bootstrap import InstallResult

    plan = _plan(tmp_path)
    layout = plan.layout
    calls = []
    app = application.ManagementApplication(layout=layout, effective_uid=lambda: 0)
    monkeypatch.setattr(
        "xferry.management.managed_state.has_unsupported_managed_state", lambda _layout: False
    )
    monkeypatch.setattr("xferry.management.managed_state.has_retained_state", lambda _layout: False)
    monkeypatch.setattr(
        "xferry.management.platform.detect_host_facts", lambda **_kwargs: plan.facts
    )
    monkeypatch.setattr("xferry.management.planning.build_setup_plan", lambda *_args: plan)
    monkeypatch.setattr(
        "xferry.management.setup.default_setup_preflight",
        lambda *_args, **_kwargs: _ok_preflight(plan),
    )

    def install(version, **options):
        calls.append(("install", version, options))
        executable = layout.release_root / "releases" / VERSION / "xferry"
        executable.parent.mkdir(parents=True)
        executable.write_bytes(b"testing executable")
        (layout.release_root / "current").symlink_to(executable.parent)
        return InstallResult(0, "runtime installed")

    def verify(*args, **options):
        calls.append(("verify", args, options))
        return _manifest()

    def execute(plan, **options):
        calls.append(("setup", plan, options))
        return OperationResult(0, "configured")

    monkeypatch.setattr("xferry.management.bootstrap.install_release", install)
    monkeypatch.setattr(release_verifier, "verify_release_envelope", verify)
    monkeypatch.setattr(
        "xferry.management.release_contract.current_platform_id", lambda: "linux-x86_64"
    )
    monkeypatch.setattr(app, "setup_native", execute)
    result = app.setup(channel="testing", version=VERSION, access="private")
    assert result.exit_code == 0
    assert calls[0] == (
        "install",
        VERSION,
        {
            "runner": app.runner,
            "channel": "testing",
            "expected_source_commit": SOURCE,
            "expected_build_id": BUILD,
        },
    )
    assert calls[1][0] == "verify"
    assert calls[1][2] == {
        "expected_version": VERSION,
        "expected_platform": "linux-x86_64",
        "channel": "testing",
    }
    assert calls[2][0] == "setup"
    artifact = calls[2][2]["testing_artifact"]
    assert artifact == {**IDENTITY, "version": VERSION, "sha256": _manifest().executable_sha256}


@pytest.fixture
def signed_envelope(tmp_path):
    payload = b"testing executable"
    manifest = _manifest(payload)
    signer = Ed25519PrivateKey.from_private_bytes(b"\x25" * 32)
    ring = ReleaseKeyRing(
        [TrustedReleaseKey("testing-unit", signer.public_key().public_bytes_raw())]
    )
    executable = tmp_path / "xferry"
    executable.write_bytes(payload)
    metadata = tmp_path / "xferry-release.json"
    metadata.write_bytes(manifest.to_bytes())
    signature = tmp_path / "xferry-release.json.sig"
    signature.write_bytes(
        create_detached_signature(
            manifest.to_bytes(),
            payload_type=TESTING_MANIFEST_SIGNATURE_TYPE,
            key_id="testing-unit",
            signer=signer,
        )
    )
    return manifest, metadata, signature, executable, ring


def test_offline_envelope_requires_testing_opt_in_and_authenticates_bytes(signed_envelope):
    manifest, metadata, signature, executable, ring = signed_envelope
    with pytest.raises(release_verifier.ReleaseEnvelopeError, match="invalid_release_version"):
        release_verifier.verify_release_envelope(
            metadata,
            signature,
            executable,
            expected_version=VERSION,
            expected_platform="linux-x86_64",
            key_ring=ring,
        )
    assert (
        release_verifier.verify_release_envelope(
            metadata,
            signature,
            executable,
            expected_version=VERSION,
            expected_platform="linux-x86_64",
            key_ring=ring,
            channel="testing",
        )
        == manifest
    )
    executable.write_bytes(b"tampered executable")
    with pytest.raises(release_verifier.ReleaseEnvelopeError, match="release_integrity_failed"):
        release_verifier.verify_release_envelope(
            metadata,
            signature,
            executable,
            expected_version=VERSION,
            expected_platform="linux-x86_64",
            key_ring=ring,
            channel="testing",
        )


@pytest.mark.parametrize("matching", [True, False])
def test_application_runtime_verification_binds_signed_envelope_to_wheel(
    testing_wheel, signed_envelope, tmp_path, monkeypatch, matching
):
    from xferry.management.model import ManagedLayout

    manifest, metadata, signature, executable, ring = signed_envelope
    release_root = tmp_path / "opt"
    release_root.mkdir()
    (release_root / "current").symlink_to(executable.parent)
    monkeypatch.setattr(release_verifier, "key_ring_for_channel", lambda _channel: ring)
    monkeypatch.setattr(
        "xferry.management.release_contract.current_platform_id", lambda: "linux-x86_64"
    )
    if not matching:
        monkeypatch.setattr(build_info, "BUILD_ID", "123.2")
        with pytest.raises(ValueError, match="same build"):
            application.ManagementApplication._verify_testing_runtime(
                ManagedLayout(release_root=release_root), VERSION
            )
    else:
        assert application.ManagementApplication._verify_testing_runtime(
            ManagedLayout(release_root=release_root), VERSION
        ) == {**IDENTITY, "version": VERSION, "sha256": manifest.executable_sha256}


def test_hidden_verifier_passes_testing_channel_and_is_hidden(monkeypatch, tmp_path, capsys):
    calls = []
    monkeypatch.setattr(
        release_verifier,
        "verify_release_envelope",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )
    paths = [tmp_path / item for item in ("manifest", "signature", "executable")]
    assert (
        cli.main(
            [
                "_verify-release-envelope",
                "--manifest",
                str(paths[0]),
                "--signature",
                str(paths[1]),
                "--executable",
                str(paths[2]),
                "--version",
                VERSION,
                "--platform",
                "linux-x86_64",
                "--channel",
                "testing",
            ]
        )
        == 0
    )
    assert calls == [
        (
            tuple(paths),
            {
                "expected_version": VERSION,
                "expected_platform": "linux-x86_64",
                "channel": "testing",
            },
        )
    ]
    capsys.readouterr()
    assert cli.main(["help"]) == 0
    assert "_verify-release-envelope" not in capsys.readouterr().out


@pytest.mark.parametrize("version", [VERSION, "0.5.1"])
def test_authenticated_health_accepts_canonical_preview_version(version):
    body = json.dumps({"health": "ready", "server": f"XFerry/{version}"}).encode()
    response = b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    result = _parse_health_response(response)
    assert result.ok and result.version == version


@pytest.mark.parametrize("version", ["0.5.1.dev01", "0.5.1.dev", "0.5.1.dev1+local"])
def test_authenticated_health_rejects_noncanonical_preview_identity(version):
    body = json.dumps({"health": "ready", "server": f"XFerry/{version}"}).encode()
    assert not _parse_health_response(b"HTTP/1.1 200 OK\r\n\r\n" + body).ok


@pytest.mark.parametrize(
    "url",
    [
        "http://example.test/asset",
        "https:///asset",
        "https://user:secret@example.test/asset",
        "https://example.test/asset#fragment",
        "file:///tmp/asset",
    ],
)
def test_metadata_reader_rejects_unsafe_urls_before_network(monkeypatch, url):
    monkeypatch.setattr(
        urllib.request, "build_opener", lambda *_args: pytest.fail("network must not run")
    )
    with pytest.raises(ValueError, match="credential-free HTTPS"):
        artifact_download.HttpsAssetReader().read(url, 100)


@pytest.mark.parametrize("size,success", [(100, True), (101, False)])
def test_metadata_reader_reads_one_extra_byte_to_enforce_exact_cap(monkeypatch, size, success):
    url = "https://assets.example.test/metadata.json"
    reads = []
    opened = []

    class Response(io.BytesIO):
        def geturl(self):
            return url

        def read(self, maximum=-1):
            reads.append(maximum)
            return super().read(maximum)

    response = Response(b"x" * size)
    monkeypatch.setattr(
        urllib.request,
        "build_opener",
        lambda *_args: SimpleNamespace(
            open=lambda *args, **kwargs: opened.append((args, kwargs)) or response
        ),
    )
    if success:
        assert artifact_download.HttpsAssetReader().read(url, 100) == b"x" * 100
    else:
        with pytest.raises(OSError, match="size limit"):
            artifact_download.HttpsAssetReader().read(url, 100)
    assert reads == [101]
    assert opened == [((url,), {"timeout": 30})]
    assert response.closed


def test_metadata_reader_rejects_downgraded_final_url(monkeypatch):
    class Response(io.BytesIO):
        def geturl(self):
            return "http://assets.example.test/metadata.json"

        def read(self, _maximum=-1):
            pytest.fail("untrusted final response must not be consumed")

    monkeypatch.setattr(
        urllib.request,
        "build_opener",
        lambda *_args: SimpleNamespace(open=lambda *_args, **_kwargs: Response()),
    )
    with pytest.raises(ValueError, match="credential-free HTTPS"):
        artifact_download.HttpsAssetReader().read("https://assets.example.test/metadata.json", 100)


def test_metadata_redirect_rejects_http_before_following():
    request = urllib.request.Request("https://assets.example.test/metadata.json")
    with pytest.raises(ValueError, match="credential-free HTTPS"):
        artifact_download._HttpsRedirect().redirect_request(
            request, io.BytesIO(), 302, "Found", HTTPMessage(), "http://cdn.example.test/asset"
        )
