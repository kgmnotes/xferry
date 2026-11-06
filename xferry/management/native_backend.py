"""Native systemd adapter with transactional profiles and conditional cleanup."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING

from xferry.settings import load_settings_text

from .channels import Channel, normalize_channel
from .compiler import compile_profile, public_url
from .configuration import configuration_diff
from .deployment import (
    Credentials,
    DeploymentSpec,
    ObservedState,
    OperationResult,
    OwnershipReceipt,
    resource_receipt,
    resource_unchanged,
    write_manifest,
)
from .execution import AdministrativeRunner
from .health import HealthEndpoint, HealthResult
from .instances import Instance, dedicated_files_folder, unregister_instance
from .model import ManagedLayout
from .ownership import restore_directory_access
from .progress import ProgressObserver, emit_progress, progress_stage, run_stage, with_progress
from .system import FilesystemTransaction, managed_mutation

if TYPE_CHECKING:
    from .releases import ReleaseManager


class NativeBackend:
    def __init__(
        self,
        runner: AdministrativeRunner,
        *,
        layout: ManagedLayout | None = None,
        effective_uid: Callable[[], int] = os.geteuid,
        release_manager: ReleaseManager | None = None,
        health_check: Callable[[HealthEndpoint, str, str, float], HealthResult] | None = None,
        root_uid: int = 0,
        progress: ProgressObserver | None = None,
    ) -> None:
        self.progress = progress
        self.root_uid = root_uid
        self.runner = runner
        self.layout = layout or ManagedLayout()
        self.effective_uid = effective_uid
        self.release_manager = release_manager
        from .health import authenticated_ping

        self.health_check = health_check or authenticated_ping

    def _require_root(self) -> None:
        if self.effective_uid() != 0:
            raise PermissionError("native deployment management requires root")

    def _validate(self, instance: Instance) -> DeploymentSpec:
        spec = instance.spec
        if (
            spec.backend != "native"
            or instance.manifest != self.layout.config_file.parent / "deployment.json"
            or spec.profile != self.layout.config_file.parent / "profile.ini"
            or spec.state_dir != self.layout.data_root
        ):
            raise ValueError("native deployment must use canonical host paths")
        return spec

    @contextmanager
    def _mutation(self, instance: Instance) -> Iterator[None]:
        self._require_root()
        with managed_mutation(
            self.layout.lock_file, effective_uid=self.effective_uid, root_uid=self.root_uid
        ):
            from .managed_state import has_unsupported_managed_state

            if has_unsupported_managed_state(self.layout):
                raise ValueError("unsupported or unsafe native state was preserved")
            self._validate(instance)
            yield

    def observe(self, instance: Instance) -> ObservedState:
        spec = self._validate(instance)
        try:
            if (
                not spec.profile.is_file()
                or not self.layout.auth_file.is_file()
                or not self.layout.config_file.is_file()
            ):
                return ObservedState(
                    "incomplete",
                    instance.id,
                    "native",
                    detail="profile, runtime configuration or credentials are missing",
                )
            privileged = self.effective_uid() == 0
            if privileged:
                compile_profile(spec.profile.read_text(), spec)
            if not self.layout.current_executable.is_file():
                return ObservedState("retained", instance.id, "native", config="valid")
            if not self.layout.unit_file.is_file():
                return ObservedState(
                    "incomplete",
                    instance.id,
                    "native",
                    config="valid",
                    detail="systemd unit is missing",
                )
            status = self.runner.run(("systemctl", "is-active", "xferry.service"))
            service = status.stdout.strip()
            if status.returncode not in {0, 3} or service not in {
                "active",
                "inactive",
                "failed",
                "activating",
                "deactivating",
                "reloading",
            }:
                raise ValueError("systemd service state could not be determined")
            enabled = (
                self.runner.run(("systemctl", "is-enabled", "xferry.service")).stdout.strip()
                or "unknown"
            )
            return ObservedState(
                "running"
                if service == "active"
                else "stopped"
                if service == "inactive"
                else "broken",
                instance.id,
                "native",
                detail=service,
                running=service == "active",
                config="valid" if privileged else "not_checked",
                enabled=enabled,
            )
        except (OSError, ValueError) as error:
            return ObservedState("broken", instance.id, "native", detail=str(error))

    def _receipt(
        self,
        spec: DeploymentSpec,
        *,
        acl: tuple[dict[str, object], ...] = (),
        changed: tuple[Path, ...] = (),
    ) -> DeploymentSpec:
        resources = {resource.path: resource for resource in spec.ownership.resources}
        for path in changed:
            resources[str(path)] = resource_receipt(
                path, kind="secret" if path == self.layout.auth_file else "file"
            )
        return replace(
            spec,
            ownership=OwnershipReceipt(
                tuple(resources.values()), acl or spec.ownership.acl, spec.ownership.accounts
            ),
        )

    def _health(self, spec: DeploymentSpec) -> bool:
        import time

        from .service import _endpoint
        from .setup import _wait_for_health

        runtime = load_settings_text(self.layout.config_file.read_text(), state_dir=spec.state_dir)
        username, password = self.layout.auth_file.read_text().strip().split(":", 1)
        endpoint = _endpoint(runtime)
        if endpoint is None:
            raise ValueError("cannot determine authenticated health endpoint")
        return run_stage(
            "wait_ready",
            lambda: _wait_for_health(
                self.health_check,
                endpoint,
                username,
                password,
                readiness_timeout=120,
                timeout=2,
                monotonic=time.monotonic,
                sleep=time.sleep,
            ),
            ok=lambda result: result.health.ok,
        ).health.ok

    @with_progress
    def configure(
        self, instance: Instance, candidate: str, *, expected_text: str, apply: bool = False
    ) -> OperationResult:
        self._require_root()
        spec = self._validate(instance)
        settings = load_settings_text(candidate, state_dir=spec.state_dir, config_path=spec.profile)
        next_spec = replace(
            spec, files_dir=Path(settings.files_dir or spec.files_dir).expanduser().absolute()
        )
        if next_spec.files_dir != spec.files_dir:
            if (spec.state_dir / ".xferry/encrypted-uploads").exists() and any(
                (spec.state_dir / ".xferry/encrypted-uploads").iterdir()
            ):
                raise ValueError(
                    "encrypted payloads and state require a coordinated storage migration"
                )
        runtime = run_stage("validate_config", lambda: compile_profile(candidate, next_spec))
        diff = configuration_diff(expected_text, candidate)
        details = {"diff": diff, "changed": candidate != expected_text}
        if not apply:
            return OperationResult(0, "Configuration is valid; no changes made.", details=details)
        with (
            dedicated_files_folder(next_spec.files_dir, exclude_id=instance.id),
            self._mutation(instance),
        ):
            if instance.spec != spec or spec.profile.read_text() != expected_text:
                raise ValueError("configuration changed during editing; retry")
            state = self.observe(instance)
            if state.state in {"broken", "incomplete", "retained"}:
                raise ValueError(
                    "native runtime needs repair before configuration can be applied; "
                    "run xferry setup"
                )
            transaction = FilesystemTransaction()
            try:
                with progress_stage("apply_config"):
                    acl = spec.ownership.acl
                    if next_spec.files_dir != spec.files_dir:
                        import pwd

                        from .managed_files import stage_managed_files_folder

                        account = pwd.getpwnam("xferry")
                        receipt = stage_managed_files_folder(
                            self.layout,
                            next_spec.files_dir,
                            transaction,
                            account.pw_uid,
                            account.pw_gid,
                            private_files=tuple(
                                Path(value)
                                for value in (
                                    settings.auth_file,
                                    settings.cert_file,
                                    settings.key_file,
                                )
                                if value
                            ),
                        )
                        acl = (*acl, *receipt)
                    for path, text in (
                        (spec.profile, candidate),
                        (self.layout.config_file, runtime),
                    ):
                        metadata = path.stat()
                        transaction.atomic_write(
                            path,
                            text.encode(),
                            mode=stat.S_IMODE(metadata.st_mode),
                            uid=metadata.st_uid,
                            gid=metadata.st_gid,
                        )
                    result = self.runner.run(
                        (
                            str(self.layout.current_executable),
                            "config",
                            "check",
                            "--config",
                            str(self.layout.config_file),
                        )
                    )
                    if result.returncode:
                        raise ValueError("installed runtime rejected the configuration")
                    next_spec = self._receipt(
                        next_spec,
                        acl=acl,
                        changed=(spec.profile, self.layout.config_file)
                        + (
                            (self.layout.unit_file,)
                            if next_spec.files_dir != spec.files_dir
                            else ()
                        ),
                    )
                    transaction.atomic_write(
                        instance.manifest,
                        (json.dumps(next_spec.to_json(), indent=2) + "\n").encode(),
                        mode=0o644,
                        uid=instance.manifest.stat().st_uid,
                        gid=instance.manifest.stat().st_gid,
                    )
                    if (
                        next_spec.files_dir != spec.files_dir
                        and self.runner.run(("systemctl", "daemon-reload")).returncode
                    ):
                        raise ValueError("could not reload systemd folder mapping")
                    if state.running:
                        restarted = run_stage(
                            "restart",
                            lambda: self.runner.run(("systemctl", "restart", "xferry.service")),
                            ok=lambda result: result.returncode == 0,
                        )
                        if restarted.returncode or not self._health(next_spec):
                            raise ValueError("service did not become healthy after configuration")
                    transaction.commit()
            except Exception as error:
                emit_progress("restore", "running")
                try:
                    transaction.rollback()
                    restored = self.runner.run(("systemctl", "daemon-reload")).returncode == 0
                    if state.running:
                        restored = (
                            self.runner.run(("systemctl", "restart", "xferry.service")).returncode
                            == 0
                            and self._health(spec)
                            and restored
                        )
                except (OSError, ValueError):
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
                    details=details,
                )
        return OperationResult(
            0,
            "Configuration applied and service is healthy."
            if state.running
            else "Configuration saved; service remains stopped.",
            details={**details, "applied": state.running},
            state=self.observe(instance),
        )

    def credentials(
        self, instance: Instance, password: str | None = None, username: str = "admin"
    ) -> OperationResult:
        self._require_root()
        spec = self._validate(instance)
        from .credentials import generate_password

        password = password or generate_password()
        if (
            not username
            or not password
            or ":" in username
            or any(c in username + password for c in "\x00\r\n")
        ):
            raise ValueError("invalid credentials")
        with self._mutation(instance):
            state = self.observe(instance)
            if state.state in {"broken", "incomplete"}:
                raise ValueError("deployment needs repair before credential rotation")
            metadata = self.layout.auth_file.stat()
            transaction = FilesystemTransaction()
            try:
                transaction.atomic_write(
                    self.layout.auth_file,
                    f"{username}:{password}\n".encode(),
                    mode=stat.S_IMODE(metadata.st_mode),
                    uid=metadata.st_uid,
                    gid=metadata.st_gid,
                )
                next_spec = self._receipt(spec, changed=(self.layout.auth_file,))
                transaction.atomic_write(
                    instance.manifest,
                    (json.dumps(next_spec.to_json(), indent=2) + "\n").encode(),
                    mode=0o644,
                    uid=instance.manifest.stat().st_uid,
                    gid=instance.manifest.stat().st_gid,
                )
                if state.running:
                    if self.runner.run(
                        ("systemctl", "restart", "xferry.service")
                    ).returncode or not self._health(spec):
                        raise ValueError("new credentials failed health validation")
                transaction.commit()
            except Exception as error:
                transaction.rollback()
                write_manifest(
                    instance.manifest, self._receipt(spec, changed=(self.layout.auth_file,))
                )
                restored = True
                if state.running:
                    restored = self.runner.run(
                        ("systemctl", "restart", "xferry.service")
                    ).returncode == 0 and self._health(spec)
                return OperationResult(
                    1,
                    f"Credential change failed: {error}; "
                    + (
                        "previous credentials restored."
                        if restored
                        else "restoration incomplete; run xferry doctor."
                    ),
                )
        settings = load_settings_text(spec.profile.read_text(), state_dir=spec.state_dir)
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
        channel: Channel | None = None,
        expected_source_commit: str | None = None,
        expected_build_id: str | None = None,
        lines: int = 100,
        since: str | None = None,
        follow: bool = False,
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
                f"Native server is {state.state}.",
                state=state,
                details={
                    "channel": spec.artifact.get("channel", "stable"),
                    "version": spec.artifact.get("version"),
                    "source_commit": spec.artifact.get("source_commit"),
                    "build_id": spec.artifact.get("build_id"),
                },
            )
        if dry_run and action not in {"update", "rollback"}:
            return OperationResult(0, f"Native {action} validated; no changes made.", state=state)
        if action == "logs":
            if not 1 <= lines <= 10000:
                raise ValueError("log lines must be between 1 and 10000")
            args = ["journalctl", "--unit", "xferry.service", "--lines", str(lines), "--no-pager"]
            if since:
                args += ["--since", since]
            if follow:
                args.append("--follow")
            stream = getattr(self.runner, "stream", None)
            if follow and callable(stream):
                return OperationResult(stream(args), "Native log stream ended.")
            result = self.runner.run(args)
            return OperationResult(
                result.returncode, "Native logs.", details={"logs": result.stdout}
            )
        self._require_root()
        if action in {"start", "stop", "restart"}:
            if action != "stop" and state.state == "retained":
                return OperationResult(
                    2,
                    "Runtime was removed; run xferry setup --backend native to resume "
                    "the retained profile.",
                    state=state,
                )
            with self._mutation(instance):
                result = self.runner.run(("systemctl", action, "xferry.service"))
            return OperationResult(
                0 if result.returncode == 0 else 1,
                f"Native {action} completed."
                if result.returncode == 0
                else f"Native {action} failed; run xferry doctor.",
                state=self.observe(instance),
            )
        if action not in {"update", "rollback", "uninstall"}:
            raise ValueError("unsupported native operation")
        manager = self.release_manager
        if manager is None:
            from .releases import default_update_manager

            selected_channel = normalize_channel(channel or spec.artifact.get("channel", "stable"))
            if (
                selected_channel == "stable"
                and expected_source_commit is None
                and expected_build_id is None
            ):
                manager = default_update_manager()
            else:
                manager = default_update_manager(
                    channel=selected_channel,
                    expected_source_commit=expected_source_commit,
                    expected_build_id=expected_build_id,
                )
        if action == "uninstall":
            unit = next(
                (
                    resource
                    for resource in spec.ownership.resources
                    if resource.path == str(self.layout.unit_file)
                ),
                None,
            )
            if self.layout.unit_file.exists() and (unit is None or not resource_unchanged(unit)):
                return OperationResult(
                    1,
                    "Systemd unit changed independently; retained for review.",
                    details={"retained": [str(self.layout.unit_file)]},
                )
            release_result = manager.uninstall(False, True, False)
            if release_result.exit_code:
                return OperationResult(release_result.exit_code, release_result.message)
            if purge:
                return self._purge(instance, spec)
            return OperationResult(
                0,
                "Native runtime removed; profile, credentials, state and files retained.",
                details={"retained": [str(spec.profile), str(spec.state_dir), str(spec.files_dir)]},
                state=self.observe(instance),
            )
        release_result = (
            manager.update(version, dry_run)
            if action == "update"
            else manager.rollback(version, dry_run)
        )
        if release_result.exit_code == 0 and not dry_run:
            with self._mutation(instance):
                latest = self._validate(instance)
                executable = self.layout.current_executable.resolve(strict=True)
                from .release_contract import MANIFEST_NAME, ReleaseManifest

                installed = ReleaseManifest.parse((executable.parent / MANIFEST_NAME).read_bytes())
                artifact: dict[str, str] = {
                    "version": executable.parent.name,
                    "sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
                    "channel": installed.channel,
                }
                if installed.source_commit is not None:
                    artifact["source_commit"] = installed.source_commit
                if installed.build_id is not None:
                    artifact["build_id"] = installed.build_id
                next_spec = replace(latest, artifact=artifact)
                if (
                    action == "rollback"
                    and spec.artifact.get("channel", "stable") == "testing"
                    and installed.channel == "stable"
                ):
                    next_spec = self._receipt(
                        next_spec,
                        changed=tuple(
                            path
                            for path in (
                                latest.profile,
                                self.layout.config_file,
                                self.layout.unit_file,
                                self.layout.auth_file,
                            )
                            if path.is_file()
                        ),
                    )
                write_manifest(instance.manifest, next_spec)
        return OperationResult(
            release_result.exit_code,
            release_result.message,
            details={
                "version": release_result.version,
                "dry_run": release_result.dry_run,
                "code": release_result.code or release_result.message,
                "detail": release_result.detail,
                "before": release_result.before,
                "target": release_result.target,
                "active": release_result.active,
                "rollback": release_result.rollback,
                "next_actions": list(release_result.next_actions),
            },
            state=self.observe(instance),
        )

    def _purge(self, instance: Instance, spec: DeploymentSpec) -> OperationResult:
        retained = [str(spec.files_dir)]
        with self._mutation(instance):
            acl_cleanup_ok = True
            for acl in spec.ownership.acl:
                if not restore_directory_access(acl):
                    acl_cleanup_ok = False
                    retained.append(str(acl.get("path")))
            for resource in spec.ownership.resources:
                path = Path(resource.path)
                if not path.exists():
                    continue
                if resource.kind in {"file", "secret"}:
                    if resource_unchanged(resource):
                        path.unlink()
                    else:
                        retained.append(str(path))
                elif resource.kind == "tree":
                    if not resource_unchanged(resource):
                        retained.append(str(path))
                        continue
                    # Public files remain even when located beneath state. Never
                    # follow symlinks while deleting private runtime-owned state.
                    for child in path.iterdir():
                        if spec.files_dir == child or spec.files_dir.is_relative_to(child):
                            continue
                        if child.is_symlink():
                            retained.append(str(child))
                        elif child.is_dir():
                            shutil.rmtree(child)
                        else:
                            child.unlink()
                    try:
                        path.rmdir()
                    except OSError:
                        pass
            from .managed_state import retained_state_path

            retained_state_path(self.layout).unlink(missing_ok=True)
            unregister_instance(instance.manifest)
            instance.manifest.unlink()
            try:
                instance.manifest.parent.rmdir()
            except OSError:
                retained.extend(str(path) for path in instance.manifest.parent.iterdir())
            # Accounts are removed only if setup created them and private state
            # and configuration no longer need the identity.
            account_safe = acl_cleanup_ok and not any(
                path.exists()
                for path in (self.layout.auth_file, self.layout.config_file, spec.profile)
            )
            import grp
            import pwd

            account = None
            try:
                account = pwd.getpwnam("xferry")
                expected_uid = next(
                    (
                        resource.uid
                        for resource in spec.ownership.resources
                        if resource.path == str(self.layout.auth_file)
                    ),
                    None,
                )
                if account.pw_uid != expected_uid:
                    account_safe = False
                for retained_root in (spec.files_dir, self.layout.data_root):
                    for folder, dirs, files in os.walk(retained_root, followlinks=False):
                        if any(
                            Path(folder, name).lstat().st_uid == account.pw_uid
                            for name in [".", *dirs, *files]
                        ):
                            account_safe = False
                            break
            except KeyError:
                pass
            except OSError:
                account_safe = False
            if not account_safe:
                retained.extend(spec.ownership.accounts)
            if account_safe:
                if "user:xferry" in spec.ownership.accounts:
                    if self.runner.run(("userdel", "xferry")).returncode:
                        retained.append("user:xferry")
                if "group:xferry" in spec.ownership.accounts:
                    try:
                        group = grp.getgrnam("xferry")
                    except KeyError:
                        # userdel may remove an empty primary group itself.
                        pass
                    else:
                        if group.gr_mem:
                            retained.append("group:xferry")
                        elif self.runner.run(("groupdel", "xferry")).returncode:
                            retained.append("group:xferry")
        return OperationResult(
            0,
            "Native deployment purged; files directory retained.",
            details={
                "retained": retained,
                "controller": "If installed separately, remove the controller "
                "with pipx uninstall xferry or its venv/package manager.",
            },
            state=ObservedState("absent", instance.id, "native"),
        )
