"""Compose adapter for the shared deployment application."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import sys
from contextlib import nullcontext
from dataclasses import replace
from pathlib import Path
from typing import TypedDict, cast

from xferry.config import __version__
from xferry.settings import load_settings_text, render_sample_profile

from .compiler import compile_profile, public_url
from .configuration import _portable_lock, edit_ini
from .credentials import generate_password
from .deployment import (
    Credentials,
    DeploymentSpec,
    ObservedState,
    OperationResult,
    OwnershipReceipt,
    load_manifest,
    resource_receipt,
    resource_unchanged,
    write_manifest,
)
from .docker_deploy import _activate, _atomic_write, _compose, _restore_bundle
from .execution import ProcessRunner, ReadDownloader
from .instances import (
    Instance,
    dedicated_files_folder,
    ensure_dedicated_files_folder,
    register_instance,
    unregister_instance,
)
from .ownership import grant_directory_access, restore_directory_access
from .progress import ProgressObserver, emit_progress, progress_stage, run_stage, with_progress


class _SnapshotFile(TypedDict):
    content: str
    sha256: str


class _StableSnapshot(TypedDict):
    schema: int
    instance_id: str
    artifact: dict[str, object]
    files: dict[str, _SnapshotFile]


class ComposeBackend:
    def __init__(
        self,
        runner: ProcessRunner,
        *,
        progress: ProgressObserver | None = None,
        reader: ReadDownloader | None = None,
    ) -> None:
        self.runner = runner
        self.progress = progress
        self.reader = reader

    def _testing_artifact(self, version: str, *, pull: bool = True) -> dict[str, object]:
        from .artifact_download import HttpsAssetReader
        from .build_identity import testing_identity, verify_testing_identity
        from .channels import MAX_TESTING_IMAGES_BYTES, manifest_url, parse_testing_images
        from .release_contract import LINUX_X86_64, MAX_MANIFEST_BYTES
        from .release_trust import MAX_SIGNATURE_BYTES, verify_signed_manifest

        testing_identity(version)
        reader = self.reader or HttpsAssetReader()
        url = manifest_url(version, LINUX_X86_64, "testing")
        manifest = verify_signed_manifest(
            reader.read(url, MAX_MANIFEST_BYTES),
            reader.read(url + ".sig", MAX_SIGNATURE_BYTES),
            channel="testing",
        )
        identity = verify_testing_identity(manifest, version)
        image = parse_testing_images(
            reader.read(url.rsplit("/", 1)[0] + "/testing-images.json", MAX_TESTING_IMAGES_BYTES),
            manifest,
        )
        if pull:
            image = self.pin_image(image)
            inspected = self.runner.run(
                ("docker", "image", "inspect", "--format", "{{json .Config.Labels}}", image)
            )
            if inspected.returncode:
                raise ValueError("could not inspect the testing image identity")
            labels = json.loads(inspected.stdout)
            expected = {
                "org.opencontainers.image.version": version,
                "org.opencontainers.image.revision": identity["source_commit"],
                "io.xferry.build-id": identity["build_id"],
                "io.xferry.channel": "testing",
            }
            if not isinstance(labels, dict) or any(labels.get(k) != v for k, v in expected.items()):
                raise ValueError("testing image and installed CLI do not belong to the same build")
        return {"image": image, "version": version, **identity}

    def _validate(self, instance: Instance) -> DeploymentSpec:
        spec = instance.spec
        output = instance.manifest.parent
        if (
            spec.backend != "docker"
            or spec.profile != output / "xferry.ini"
            or spec.state_dir != output / "state"
        ):
            raise ValueError("Docker profile and state must belong to the selected bundle")
        if output.is_symlink():
            raise ValueError("deployment bundle must not be a symlink")
        allowed = {
            output,
            spec.profile,
            output / "runtime.ini",
            output / "compose.yaml",
            output / "secrets/xferry_auth",
            output / ".xferry-history.json",
            output / ".xferry-last-stable.json",
        }
        expected_uid = getattr(os, "geteuid", lambda: output.stat().st_uid)()
        for entry in (output, instance.manifest, *allowed):
            current = entry
            while current != current.parent:
                if current.is_symlink():
                    raise ValueError("deployment ownership paths must not contain symlinks")
                current = current.parent
            if entry.exists() and entry in {output, instance.manifest}:
                metadata = entry.stat()
                if metadata.st_uid != expected_uid or (
                    os.name != "nt" and metadata.st_mode & 0o022
                ):
                    raise ValueError(
                        "deployment bundle must be protected and owned by the current operator"
                    )
        for resource in spec.ownership.resources:
            path = Path(resource.path)
            if path not in allowed:
                raise ValueError("ownership receipt refers outside generated deployment resources")
            if resource.kind == "directory" and path == output and not resource_unchanged(resource):
                raise ValueError("deployment bundle directory identity changed")
        if any(Path(str(acl.get("path"))) != spec.files_dir for acl in spec.ownership.acl):
            raise ValueError("ACL receipt does not belong to the deployment files directory")
        return spec

    @staticmethod
    def state_storage(spec: DeploymentSpec) -> dict[str, str]:
        return {
            "kind": "docker_volume",
            "name": str(spec.backend_options["project"]) + "_xferry-data",
            "runtime_root": "/data",
        }

    def _prefix(self, instance: Instance) -> tuple[str, ...]:
        spec = self._validate(instance)
        return (
            "docker",
            "compose",
            "-p",
            str(spec.backend_options["project"]),
            "-f",
            str(instance.manifest.parent / "compose.yaml"),
        )

    def _ownership(self, spec: DeploymentSpec) -> None:
        compose = spec.profile.parent / "compose.yaml"
        receipt = next(
            (resource for resource in spec.ownership.resources if resource.path == str(compose)),
            None,
        )
        if receipt is None or not resource_unchanged(receipt):
            raise ValueError("Compose file changed independently; retained for review")
        project = str(spec.backend_options["project"])
        result = self.runner.run(
            (
                "docker",
                "ps",
                "-a",
                "--filter",
                f"label=com.docker.compose.project={project}",
                "--format",
                '{{.Label "io.xferry.managed"}}',
            )
        )
        if result.returncode or any(line != "true" for line in result.stdout.splitlines()):
            raise ValueError(
                "Compose project contains containers not owned by XFerry or Docker is unavailable"
            )

    def observe(self, instance: Instance) -> ObservedState:
        spec = self._validate(instance)
        try:
            self._ownership(spec)
            output = instance.manifest.parent
            if (
                not spec.profile.is_file()
                or not (output / "runtime.ini").is_file()
                or not (output / "secrets/xferry_auth").is_file()
            ):
                return ObservedState(
                    "incomplete", instance.id, "docker", detail="deployment bundle is incomplete"
                )
            compile_profile(spec.profile.read_text(), spec)
            result = self.runner.run((*self._prefix(instance), "ps", "--all", "--format", "json"))
            if result.returncode:
                raise ValueError("Docker state probe failed")
            text = result.stdout.strip()
            if not text:
                containers = []
            elif text.startswith("["):
                containers = json.loads(text)
            else:
                containers = [json.loads(line) for line in text.splitlines() if line.strip()]
            app = [item for item in containers if item.get("Service") == "xferry"]
            if not app:
                return ObservedState("retained", instance.id, "docker", config="valid")
            running = any(item.get("State") == "running" for item in app)
            broken = any(item.get("State") in {"dead", "restarting", "removing"} for item in app)
            return ObservedState(
                "broken" if broken else "running" if running else "stopped",
                instance.id,
                "docker",
                running=running,
                config="valid",
            )
        except (OSError, ValueError, TypeError, KeyError) as error:
            return ObservedState("broken", instance.id, "docker", detail=str(error))

    @with_progress
    def pin_image(self, image: str) -> str:
        if not (
            re.fullmatch(r"ghcr\.io/kgmnotes/xferry:v[0-9][a-zA-Z0-9.+-]*", image)
            or re.fullmatch(r"[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}", image)
        ):
            raise ValueError("an exact XFerry image version or digest is required")
        result = run_stage(
            "download",
            lambda: self.runner.run(("docker", "pull", image)),
            ok=lambda result: result.returncode == 0,
        )
        if result.returncode:
            raise ValueError("could not pull the selected XFerry image")
        result = self.runner.run(
            ("docker", "image", "inspect", "--format", "{{json .RepoDigests}}", image)
        )
        if result.returncode:
            raise ValueError("could not read the downloaded image digest")
        digests = json.loads(result.stdout)
        candidates = [
            value
            for value in digests
            if isinstance(value, str)
            and re.fullmatch(r"[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}", value)
            and value.split("@", 1)[0] == image.split("@", 1)[0].split(":v", 1)[0]
        ]
        if "@sha256:" in image and image not in candidates:
            raise ValueError("downloaded image digest differs from the selected artifact")
        if not candidates:
            raise ValueError("downloaded image has no verifiable XFerry repository digest")
        return image if image in candidates else candidates[0]

    def _compose(self, spec: DeploymentSpec, text: str) -> bytes:
        settings = load_settings_text(text, state_dir=spec.state_dir, config_path=spec.profile)
        hostname = public_url(settings).split("://", 1)[1].split(":", 1)[0].rstrip("/")
        return _compose(
            str(spec.backend_options["project"]),
            spec.profile.parent,
            spec.files_dir,
            not settings.effective_tls_enabled(),
            hostname,
            image=str(spec.artifact["image"]),
            published_port=settings.port,
            acme_port=settings.acme_http_port,
        )

    def _receipt(
        self,
        spec: DeploymentSpec,
        *,
        acl: tuple[dict[str, object], ...] = (),
        changed: tuple[Path, ...] = (),
    ) -> DeploymentSpec:
        output = spec.profile.parent
        resources = {resource.path: resource for resource in spec.ownership.resources}
        if not resources:
            changed = (
                spec.profile,
                output / "runtime.ini",
                output / "compose.yaml",
                output / "secrets/xferry_auth",
            )
            resources[str(output)] = resource_receipt(output, kind="directory")
        for path in changed:
            resources[str(path)] = resource_receipt(
                path, kind="secret" if path.name == "xferry_auth" else "file"
            )
        return replace(
            spec, ownership=OwnershipReceipt(tuple(resources.values()), acl or spec.ownership.acl)
        )

    @with_progress
    def setup(
        self,
        output: Path,
        *,
        files_dir: Path | None = None,
        version: str | None = None,
        access: str = "public",
        domain: str | None = None,
        public_ip: str | None = None,
        email: str | None = None,
        dry_run: bool = False,
        image: str | None = None,
        channel: str = "stable",
        **_: object,
    ) -> OperationResult:
        from .channels import image_reference, normalize_channel

        selected_channel = normalize_channel(channel)
        testing_artifact = (
            self._testing_artifact(version or __version__, pull=False)
            if selected_channel == "testing"
            else None
        )
        output = output.expanduser().absolute()
        manifest = output / ".xferry-deployment.json"
        if output.is_symlink():
            raise ValueError("deployment directory must not be a symlink")
        if manifest.exists():
            old = load_manifest(manifest)
            if old.backend != "docker":
                raise ValueError("deployment belongs to another backend")
            if old.artifact.get("channel", "stable") != selected_channel:
                raise ValueError(
                    "Use update with an explicit --channel to switch this installation."
                )
            item = Instance(old.instance_id, old.backend, old.profile, manifest)
            if dry_run:
                return OperationResult(
                    0, "Existing deployment validated; no changes made.", state=self.observe(item)
                )
            return self.operate("start", item)
        if output.exists():
            entries = tuple(output.iterdir())
            if any(
                path.name != ".xferry.ini.lock"
                or path.is_symlink()
                or not path.is_file()
                or path.stat().st_nlink != 1
                for path in entries
            ):
                raise ValueError(
                    "deployment directory is not empty; unsupported state was preserved"
                )
        files = Path(files_dir or output.parent / (output.name + "-files")).expanduser().absolute()
        if (
            output.is_relative_to(files)
            or files.is_relative_to(output)
            or files == Path(files.anchor)
        ):
            raise ValueError("files directory and private deployment bundle must be separate")
        if files.is_symlink() or (files.exists() and not files.is_dir()):
            raise ValueError("files directory must be a real directory")
        ensure_dedicated_files_folder(files)
        from xferry.security.tls import (
            normalize_domain,
            resolve_public_ipv4,
            sslip_domain_for_ip,
            validate_public_ipv4,
        )

        private = access in {"private", "lab"}
        values = {
            "files_dir": str(files),
            "auth_file": str(output / "secrets/xferry_auth"),
            "access": access,
            "host": "127.0.0.1" if private else "0.0.0.0",  # nosec B104 - explicit public mode
            "port": 8080 if private else 443,
            "https_mode": "off" if private else "domain" if domain else "auto",
        }
        if domain:
            values["domain"] = normalize_domain(domain)
            values["allowed_hosts"] = values["domain"]
        elif not private:
            address = run_stage(
                "preflight",
                lambda: validate_public_ipv4(public_ip) if public_ip else resolve_public_ipv4(),
            )
            values["public_ip"] = address
            values["allowed_hosts"] = sslip_domain_for_ip(address)
        else:
            values["allowed_hosts"] = "localhost 127.0.0.1"
        if email:
            values["email"] = email
        text = edit_ini(render_sample_profile("docker"), values)
        text = re.sub(r"(?m)^[ \t]*state_dir[ \t]*=.*(?:\r?\n|$)", "", text)
        # Read-only validation and an explicit no-mutation preview precede pull/mkdir.
        settings = run_stage(
            "preflight",
            lambda: load_settings_text(
                text, state_dir=output / "state", config_path=output / "xferry.ini"
            ),
        )
        settings.to_server_config()
        if dry_run:
            return OperationResult(
                0,
                "Compose setup validated; no files or containers changed.",
                details={
                    "bundle": str(output),
                    "files_dir": str(files),
                    "profile": str(output / "xferry.ini"),
                    "image": (testing_artifact or {}).get("image")
                    or image
                    or image_reference(version or __version__, selected_channel),
                    "channel": selected_channel,
                },
                url=public_url(settings),
            )
        artifact_version = version if image is not None else version or __version__
        with dedicated_files_folder(files):
            if selected_channel == "testing":
                testing_artifact = self._testing_artifact(version or __version__)
                image = str(testing_artifact["image"])
            else:
                image = self.pin_image(image or image_reference(version or __version__))
            project = "xferry-" + os.urandom(6).hex()
            state_storage = {
                "kind": "docker_volume",
                "name": project + "_xferry-data",
                "runtime_root": "/data",
            }
            spec = DeploymentSpec.new(
                "docker",
                output / "xferry.ini",
                files,
                output / "state",
                testing_artifact or {"image": image, "version": artifact_version},
                backend_options={
                    "project": project,
                    "state_storage": state_storage,
                    "credentials_revealed": False,
                },
            )
            output.mkdir(parents=True, exist_ok=True, mode=0o700)
            with _portable_lock(output / "xferry.ini"):
                acl = None
                snapshots = dict.fromkeys(
                    (
                        spec.profile,
                        output / "runtime.ini",
                        output / "compose.yaml",
                        output / "secrets/xferry_auth",
                    )
                )
                try:
                    with progress_stage("prepare"):
                        files.mkdir(parents=True, exist_ok=True, mode=0o750)
                        acl = (
                            grant_directory_access(files, 10001)
                            if sys.platform == "linux"
                            else None
                        )
                        password = generate_password()
                        _atomic_write(
                            output / "secrets/xferry_auth", f"admin:{password}\n".encode(), 0o600
                        )
                        _atomic_write(spec.profile, text.encode(), 0o600)
                        _atomic_write(
                            output / "runtime.ini", compile_profile(text, spec).encode(), 0o644
                        )
                        _atomic_write(output / "compose.yaml", self._compose(spec, text), 0o600)
                        spec = self._receipt(spec, acl=(acl,) if acl else ())
                        write_manifest(manifest, spec)
                        register_instance(manifest)
                        item = Instance(spec.instance_id, "docker", spec.profile, manifest)
                    _activate(self.runner, self._prefix(item))
                    spec = replace(
                        spec, backend_options={**spec.backend_options, "credentials_revealed": True}
                    )
                    write_manifest(manifest, spec)
                except Exception:
                    emit_progress("restore", "running")
                    restored = True
                    if acl:
                        restored = restore_directory_access(acl)
                    if not manifest.exists():
                        restored = _restore_bundle(snapshots) and restored
                    # Keep all generated state/auth for inspection/retry. No active
                    # service survives a failed first setup.
                    prefix = (
                        "docker",
                        "compose",
                        "-p",
                        str(spec.backend_options["project"]),
                        "-f",
                        str(output / "compose.yaml"),
                    )
                    stopped = self.runner.run((*prefix, "down", "--remove-orphans"))
                    emit_progress(
                        "restore", "done" if restored and stopped.returncode == 0 else "failed"
                    )
                    raise
            return OperationResult(
                0,
                "Docker server is healthy.",
                details={
                    "bundle": str(output),
                    "state_storage": state_storage,
                    "instance_id": spec.instance_id,
                    "files_dir": str(files),
                },
                credentials=Credentials("admin", password, public_url(settings)),
                url=public_url(settings),
                state=self.observe(item),
            )

    @with_progress
    def configure(
        self, instance: Instance, candidate: str, *, expected_text: str, apply: bool = False
    ) -> OperationResult:
        spec = self._validate(instance)
        output = instance.manifest.parent
        from .configuration import configuration_diff

        changes = {
            "diff": configuration_diff(expected_text, candidate),
            "changed": candidate != expected_text,
        }
        resolved = load_settings_text(candidate, state_dir=spec.state_dir, config_path=spec.profile)
        next_spec = replace(
            spec, files_dir=Path(resolved.files_dir or spec.files_dir).expanduser().absolute()
        )
        if next_spec.files_dir != spec.files_dir:
            raise ValueError("changing persistent storage requires an explicit data migration")
        runtime = run_stage("validate_config", lambda: compile_profile(candidate, next_spec))
        if not apply:
            return OperationResult(0, "Configuration is valid; no changes made.", details=changes)
        with _portable_lock(instance.config):
            if instance.spec != spec or instance.config.read_text() != expected_text:
                raise ValueError("configuration changed during editing; retry")
            self._ownership(spec)
            state = self.observe(instance)
            if state.state in {"broken", "incomplete"}:
                raise ValueError("deployment needs repair before editing; run xferry doctor")
            paths = (
                spec.profile,
                output / "runtime.ini",
                output / "compose.yaml",
                instance.manifest,
            )
            snapshots = {path: path.read_bytes() for path in paths}
            try:
                with progress_stage("apply_config"):
                    _atomic_write(spec.profile, candidate.encode(), 0o600)
                    _atomic_write(output / "runtime.ini", runtime.encode(), 0o644)
                    _atomic_write(output / "compose.yaml", self._compose(spec, candidate), 0o600)
                    write_manifest(
                        instance.manifest,
                        self._receipt(
                            spec,
                            changed=(spec.profile, output / "runtime.ini", output / "compose.yaml"),
                        ),
                    )
                    if state.running:
                        _activate(self.runner, self._prefix(instance))
            except Exception as error:
                emit_progress("restore", "running")
                restored = _restore_bundle(snapshots)
                if restored and state.running:
                    try:
                        _activate(self.runner, self._prefix(instance))
                    except (OSError, RuntimeError):
                        restored = False
                emit_progress("restore", "done" if restored else "failed")
                return OperationResult(
                    1,
                    f"Configuration failed: {error}. "
                    + (
                        "Previous configuration and runtime state restored."
                        if restored
                        else "Restoration incomplete; run xferry doctor."
                    ),
                    details=changes,
                )
        return OperationResult(
            0,
            "Configuration applied."
            if state.running
            else "Configuration saved; server remains stopped.",
            details={**changes, "applied": state.running},
            state=self.observe(instance),
        )

    def credentials(
        self, instance: Instance, password: str | None = None, username: str = "admin"
    ) -> OperationResult:
        spec = self._validate(instance)
        path = spec.profile.parent / "secrets/xferry_auth"
        password = password or generate_password()
        if (
            any(c in username + password for c in "\x00\r\n")
            or ":" in username
            or not username
            or not password
        ):
            raise ValueError("invalid credentials")
        settings = load_settings_text(spec.profile.read_text(), state_dir=spec.state_dir)
        with _portable_lock(instance.config):
            if instance.spec != spec:
                raise ValueError("deployment changed during preparation; retry")
            self._ownership(spec)
            state = self.observe(instance)
            before = path.read_bytes()
            try:
                _atomic_write(path, f"{username}:{password}\n".encode(), 0o600)
                write_manifest(instance.manifest, self._receipt(spec, changed=(path,)))
                _activate(self.runner, self._prefix(instance), start=state.running)
            except Exception as error:
                _atomic_write(path, before, 0o600)
                write_manifest(instance.manifest, self._receipt(spec, changed=(path,)))
                try:
                    _activate(self.runner, self._prefix(instance), start=state.running)
                except (OSError, RuntimeError):
                    return OperationResult(
                        1, "Credential change and runtime restoration failed; run xferry doctor."
                    )
                return OperationResult(
                    1, f"Credential change failed; previous credentials restored: {error}"
                )
        return OperationResult(
            0,
            "Credentials changed.",
            credentials=Credentials(username, password, public_url(settings)),
        )

    def operate(
        self,
        action: str,
        instance: Instance,
        *,
        dry_run: bool = False,
        purge: bool = False,
        confirmed: bool = False,
        version: str | None = None,
        lines: int = 100,
        since: str | None = None,
        follow: bool = False,
        channel: str | None = None,
        **_: object,
    ) -> OperationResult:
        if action == "uninstall" and purge and not dry_run and confirmed is not True:
            return OperationResult(
                2, "Purge requires confirmation; use --yes or confirm the prompt."
            )
        spec = self._validate(instance)
        state = self.observe(instance)
        if action == "status":
            return OperationResult(
                1 if state.state in {"broken", "incomplete"} else 0,
                f"Docker server is {state.state}.",
                state=state,
                details={
                    "state_storage": self.state_storage(spec),
                    "files_dir": str(spec.files_dir),
                    "profile": str(spec.profile),
                    "channel": spec.artifact.get("channel", "stable"),
                    "version": spec.artifact.get("version"),
                    "source_commit": spec.artifact.get("source_commit"),
                    "build_id": spec.artifact.get("build_id"),
                },
            )
        if dry_run and action not in {"update", "rollback"}:
            return OperationResult(0, f"Docker {action} validated; no changes made.", state=state)
        if action == "logs":
            if not 1 <= lines <= 10000:
                raise ValueError("log lines must be between 1 and 10000")
            args = [*self._prefix(instance), "logs", "--no-color", "--tail", str(lines)]
            if since:
                args += ["--since", since]
            if follow:
                args.append("--follow")
            args.append("xferry")
            stream = getattr(self.runner, "stream", None)
            if follow and callable(stream):
                return OperationResult(stream(args), "Docker log stream ended.")
            result = self.runner.run(args)
            return OperationResult(
                result.returncode, "Docker logs.", details={"logs": result.stdout}
            )
        if action in {"update", "rollback"}:
            return self._release(action, instance, version, channel=channel, dry_run=dry_run)
        if action not in {"start", "stop", "restart", "uninstall"}:
            raise ValueError("unsupported Docker operation")
        purge_result = None
        revealed_credentials = None
        with _portable_lock(instance.config):
            if instance.spec != spec:
                raise ValueError("deployment changed during preparation; retry")
            self._ownership(spec)
            if action in {"start", "restart"}:
                acl = (
                    grant_directory_access(spec.files_dir, 10001)
                    if sys.platform == "linux"
                    else None
                )
                before_manifest = instance.manifest.read_bytes()
                try:
                    if acl:
                        receipts = tuple(
                            receipt
                            for receipt in spec.ownership.acl
                            if receipt.get("path") != str(spec.files_dir)
                        ) + (acl,)
                        write_manifest(instance.manifest, self._receipt(spec, acl=receipts))
                    _activate(self.runner, self._prefix(instance))
                    if spec.backend_options.get("credentials_revealed") is False:
                        username, password = (
                            (spec.profile.parent / "secrets/xferry_auth")
                            .read_text()
                            .strip()
                            .split(":", 1)
                        )
                        settings = load_settings_text(
                            spec.profile.read_text(), state_dir=spec.state_dir
                        )
                        revealed_credentials = Credentials(username, password, public_url(settings))
                        current = instance.spec
                        write_manifest(
                            instance.manifest,
                            replace(
                                current,
                                backend_options={
                                    **current.backend_options,
                                    "credentials_revealed": True,
                                },
                            ),
                        )
                except (OSError, RuntimeError, ValueError):
                    if acl:
                        restore_directory_access(acl)
                        _atomic_write(instance.manifest, before_manifest, 0o600)
                    if not state.running:
                        self.runner.run((*self._prefix(instance), "stop", "xferry"))
                    raise
            elif action == "stop":
                result = self.runner.run((*self._prefix(instance), "stop", "xferry"))
                if result.returncode:
                    raise ValueError("Docker server could not be stopped")
            elif action == "uninstall":
                args = [*self._prefix(instance), "down", "--remove-orphans"]
                if purge:
                    args.append("--volumes")
                if self.runner.run(args).returncode:
                    raise ValueError("Docker server could not be removed")
                if purge:
                    purge_result = self._purge(instance, spec)
        if purge_result is not None:
            lock = instance.config.with_name(f".{instance.config.name}.lock")
            lock.unlink(missing_ok=True)
            try:
                instance.manifest.parent.rmdir()
            except OSError:
                pass
            return purge_result
        return OperationResult(
            0,
            f"Docker {action} completed.",
            credentials=revealed_credentials,
            state=self.observe(instance),
            details={
                "state_storage": self.state_storage(spec),
                "retained": [
                    str(spec.profile),
                    str(spec.files_dir),
                    "docker-volume:" + str(self.state_storage(spec)["name"]),
                    "docker-volume:" + str(spec.backend_options["project"]) + "_xferry-secrets",
                ],
            }
            if action == "uninstall"
            else {},
        )

    def _purge(self, instance: Instance, spec: DeploymentSpec) -> OperationResult:
        retained = []
        for acl in spec.ownership.acl:
            if not restore_directory_access(acl):
                retained.append(str(acl.get("path")))
        for resource in spec.ownership.resources:
            path = Path(resource.path)
            if resource.kind not in {"file", "secret"} or not path.exists():
                continue
            if resource_unchanged(resource):
                path.unlink()
            else:
                retained.append(str(path))
        unregister_instance(instance.manifest)
        instance.manifest.unlink()
        for folder in (spec.profile.parent / "secrets", spec.profile.parent):
            try:
                folder.rmdir()
            except OSError:
                if folder == spec.profile.parent:
                    retained.extend(
                        str(p) for p in folder.iterdir() if p.name != ".xferry.ini.lock"
                    )
        # Release the lock before removing its stable inode and now-empty bundle.
        return OperationResult(
            0,
            "Docker deployment purged; files directory retained.",
            details={
                "retained": list(dict.fromkeys([str(spec.files_dir), *retained])),
                "controller": "If installed separately, remove the controller "
                "with pipx uninstall xferry or its venv/package manager.",
            },
            state=ObservedState("absent", instance.id, "docker"),
        )

    def _protected_payload(self, spec: DeploymentSpec, path: Path, limit: int) -> bytes:
        receipt = next((item for item in spec.ownership.resources if item.path == str(path)), None)
        metadata = path.lstat()
        expected_uid = getattr(os, "geteuid", lambda: metadata.st_uid)()
        if (
            receipt is None
            or not resource_unchanged(receipt)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != expected_uid
            or metadata.st_size > limit
            or (os.name != "nt" and metadata.st_mode & 0o022)
        ):
            raise ValueError(f"{path.name} changed independently; retained for review")
        return path.read_bytes()

    def _stable_snapshot(self, spec: DeploymentSpec) -> _StableSnapshot | None:
        path = spec.profile.parent / ".xferry-last-stable.json"
        if not path.exists() and not path.is_symlink():
            return None
        try:
            document = json.loads(self._protected_payload(spec, path, 5 * 1024 * 1024))
            if (
                not isinstance(document, dict)
                or set(document) != {"schema", "instance_id", "artifact", "files"}
                or type(document["schema"]) is not int
                or document["schema"] != 1
                or document["instance_id"] != spec.instance_id
                or not isinstance(document["artifact"], dict)
                or document["artifact"].get("channel", "stable") != "stable"
            ):
                raise ValueError
            files = document["files"]
            if not isinstance(files, dict) or set(files) != {
                "xferry.ini",
                "runtime.ini",
                "compose.yaml",
            }:
                raise ValueError
            for entry in files.values():
                if not isinstance(entry, dict) or set(entry) != {"content", "sha256"}:
                    raise ValueError
                payload = base64.b64decode(entry["content"], validate=True)
                if (
                    len(payload) > 1024 * 1024
                    or hashlib.sha256(payload).hexdigest() != entry["sha256"]
                ):
                    raise ValueError
            return cast(_StableSnapshot, document)
        except (OSError, ValueError, KeyError, TypeError):
            raise ValueError(
                "Stable snapshot changed or is invalid; preserved for review"
            ) from None

    def _save_stable_snapshot(self, spec: DeploymentSpec) -> None:
        files = {}
        for name in ("xferry.ini", "runtime.ini", "compose.yaml"):
            payload = self._protected_payload(spec, spec.profile.parent / name, 1024 * 1024)
            files[name] = {
                "content": base64.b64encode(payload).decode("ascii"),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        document = {
            "schema": 1,
            "instance_id": spec.instance_id,
            "artifact": dict(spec.artifact),
            "files": files,
        }
        _atomic_write(
            spec.profile.parent / ".xferry-last-stable.json",
            (json.dumps(document, indent=2) + "\n").encode(),
            0o600,
        )

    def _release(
        self,
        action: str,
        instance: Instance,
        version: str | None,
        *,
        channel: str | None = None,
        dry_run: bool = False,
    ) -> OperationResult:
        from .channels import image_reference, normalize_channel, validate_version_for_channel
        from .versions import MIN_DEPLOYMENT_RELEASE, compare_release_versions

        spec = self._validate(instance)
        selected_channel = normalize_channel(channel or spec.artifact.get("channel", "stable"))
        if action == "rollback" and selected_channel == "testing" and version is None:
            from xferry.config import __version__ as controller_version

            version = controller_version
        output = spec.profile.parent
        history_path = output / ".xferry-history.json"
        stable_path = output / ".xferry-last-stable.json"
        with nullcontext() if dry_run else _portable_lock(instance.config):
            if instance.spec != spec:
                raise ValueError("deployment changed during preparation; retry")
            self._ownership(spec)
            state = self.observe(instance)
            if state.state in {"broken", "incomplete", "retained"}:
                raise ValueError(
                    "deployment needs repair before a release change; run xferry doctor"
                )
            history = (
                json.loads(self._protected_payload(spec, history_path, 64 * 1024))
                if history_path.exists() or history_path.is_symlink()
                else []
            )
            if (
                not isinstance(history, list)
                or len(history) > 5
                or any(not isinstance(item, dict) for item in history)
            ):
                raise ValueError("release history is invalid; preserved for review")
            stable = self._stable_snapshot(spec)
            restored_files: dict[Path, bytes] = {}
            history_index = None
            if action == "update":
                if version is None:
                    raise ValueError("update requires an exact supported version")
                validate_version_for_channel(version, selected_channel)
                if compare_release_versions(version, MIN_DEPLOYMENT_RELEASE) < 0:
                    raise ValueError("update requires an exact supported version")
                if selected_channel == "testing":
                    artifact = self._testing_artifact(version, pull=not dry_run)
                else:
                    reference = image_reference(version)
                    image = reference if dry_run else self.pin_image(reference)
                    artifact = {"image": image, "version": version, "channel": "stable"}
            elif (
                selected_channel == "stable" and spec.artifact.get("channel", "stable") == "testing"
            ):
                if stable is None:
                    raise ValueError("no compatible stable snapshot is available")
                artifact = dict(stable["artifact"])
                if version is not None and artifact.get("version") != version:
                    raise ValueError("requested rollback version differs from the stable snapshot")
                for name, entry in stable["files"].items():
                    restored_files[output / name] = base64.b64decode(
                        entry["content"], validate=True
                    )
                history_index = next(
                    (index for index, item in enumerate(history) if item == artifact), None
                )
            else:
                candidates = [
                    (index, item)
                    for index, item in enumerate(history)
                    if item.get("channel", "stable") == selected_channel
                    and (version is None or item.get("version") == version)
                ]
                if not candidates:
                    raise ValueError("no current-format rollback artifact is available")
                history_index, artifact = candidates[-1]
                artifact = dict(artifact)
                if selected_channel == "testing":
                    target_version = artifact.get("version")
                    if not isinstance(target_version, str):
                        raise ValueError("testing rollback artifact has no version")
                    verified = self._testing_artifact(target_version, pull=not dry_run)
                    if artifact != verified:
                        raise ValueError(
                            "testing rollback artifact does not match the signed build"
                        )
            artifact_image = artifact.get("image")
            if (
                not isinstance(artifact_image, str)
                or (not dry_run or action == "rollback")
                and re.fullmatch(r"[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}", artifact_image)
                is None
            ):
                raise ValueError("release artifact must pin an immutable image digest")
            candidate = replace(spec, artifact=artifact)
            profile = restored_files.get(spec.profile, spec.profile.read_bytes()).decode()
            compile_profile(profile, candidate)
            compose = self._compose(candidate, profile)
            if restored_files and restored_files[output / "compose.yaml"] != compose:
                raise ValueError("stable snapshot does not match this deployment")
            if dry_run:
                return OperationResult(
                    0,
                    f"Docker {action} validated; no changes made.",
                    state=state,
                    details={"dry_run": True, "channel": selected_channel, **artifact},
                )
            before = {
                path: path.read_bytes() if path.exists() else None
                for path in (
                    spec.profile,
                    output / "runtime.ini",
                    output / "compose.yaml",
                    instance.manifest,
                    history_path,
                    stable_path,
                )
            }
            changed = [output / "compose.yaml"]
            try:
                if (
                    selected_channel == "testing"
                    and spec.artifact.get("channel", "stable") == "stable"
                ):
                    self._save_stable_snapshot(spec)
                    changed.append(stable_path)
                for path, payload in restored_files.items():
                    _atomic_write(path, payload)
                    if path not in changed:
                        changed.append(path)
                _atomic_write(output / "compose.yaml", compose)
                candidate = self._receipt(candidate, changed=tuple(changed))
                write_manifest(instance.manifest, candidate)
                _activate(self.runner, self._prefix(instance), start=state.running)
                if action == "update":
                    history.append(dict(spec.artifact))
                elif history_index is not None:
                    history.pop(history_index)
                _atomic_write(history_path, (json.dumps(history[-5:], indent=2) + "\n").encode())
                write_manifest(instance.manifest, self._receipt(candidate, changed=(history_path,)))
            except Exception as error:
                restored = _restore_bundle(before)
                try:
                    if restored:
                        _activate(self.runner, self._prefix(instance), start=state.running)
                except (OSError, RuntimeError, ValueError):
                    restored = False
                return OperationResult(
                    1,
                    f"Docker {action} failed: {error}; "
                    + (
                        "previous artifact and configuration restored."
                        if restored
                        else "restoration incomplete; run xferry doctor."
                    ),
                )
        return OperationResult(0, f"Docker {action} completed.", state=self.observe(instance))
