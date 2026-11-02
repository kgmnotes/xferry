"""Single management application used by command line and interactive setup.

Every persistent action resolves a schema-2 identity before selecting an adapter.
Foreground profiles remain outside this deployment registry.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from .execution import AdministrativeRunner, CommandRunner

if TYPE_CHECKING:
    from .compose_backend import ComposeBackend
    from .model import ManagedLayout, ResourceOverrides, SetupPlan
    from .native_backend import NativeBackend
    from .setup import CredentialsResult, SetupExecutor, SetupResult

from .configuration import edit_ini
from .deployment import ObservedState, OperationPlan, OperationResult, load_manifest
from .instances import (
    Instance,
    dedicated_files_folder,
    deployment_setup_lock,
    discover_instances,
    ensure_dedicated_files_folder,
    register_instance,
    resolve_instance,
    user_data_dir,
)


class ManagementApplication:
    def __init__(
        self,
        *,
        runner: AdministrativeRunner | None = None,
        native_backend: NativeBackend | None = None,
        compose_backend: ComposeBackend | None = None,
        layout: ManagedLayout | None = None,
        effective_uid: Callable[[], int] | None = None,
    ) -> None:
        self.runner = runner or CommandRunner()
        self._native_backend = native_backend
        self._compose_backend = compose_backend
        self.layout = layout
        self.effective_uid: Callable[[], int] = (
            effective_uid
            if effective_uid is not None
            else lambda: getattr(os, "geteuid", lambda: -1)()
        )

    def instances(self) -> tuple[Instance, ...]:
        return discover_instances()

    def resolve(self, instance: str | Path | Instance | None = None) -> Instance:
        return resolve_instance(instance)

    def _backend(self, instance: Instance) -> NativeBackend | ComposeBackend:
        backend = instance.spec.backend
        if backend == "docker":
            if self._compose_backend is None:
                from .compose_backend import ComposeBackend

                self._compose_backend = ComposeBackend(self.runner)
            return self._compose_backend
        if self._native_backend is None:
            import sys

            if sys.platform != "linux":
                raise ValueError(
                    "native deployment requires a supported Linux/systemd host; "
                    "choose Docker or foreground run"
                )
            from .native_backend import NativeBackend

            self._native_backend = NativeBackend(
                self.runner, layout=self.layout, effective_uid=self.effective_uid
            )
        return self._native_backend

    def observe(self, instance: str | Path | Instance | None = None) -> ObservedState:
        try:
            selected = self.resolve(instance)
        except ValueError as error:
            if instance is None and not self.instances():
                return ObservedState("absent", detail=str(error))
            raise
        return self._backend(selected).observe(selected)

    def operate(
        self, action: str, instance: str | Path | Instance | None = None, **options: Any
    ) -> OperationResult:
        if "purge_data" in options:
            raise ValueError("use purge=True; the old purge-data workflow is unsupported")
        if (
            action == "uninstall"
            and options.get("purge", False)
            and not options.get("dry_run", False)
            and options.get("confirmed") is not True
        ):
            return OperationResult(
                2, "Purge requires confirmation; use --yes or confirm the prompt."
            )
        selected = self.resolve(instance)
        if action == "uninstall" and not options.get("dry_run", False):
            with deployment_setup_lock():
                return self._backend(selected).operate(action, selected, **options)
        return self._backend(selected).operate(action, selected, **options)

    def configure(
        self,
        instance: str | Path | Instance | None,
        changes: Mapping[str, object],
        *,
        apply: bool = False,
        expected_text: str | None = None,
    ) -> OperationResult:
        selected = self.resolve(instance)
        before = selected.config.read_text(encoding="utf-8")
        if expected_text is not None and expected_text != before:
            raise ValueError("configuration changed during editing; retry")
        protected = {"auth", "auth_file", "state_dir", "config_version"} & set(changes)
        if protected:
            raise ValueError(
                "deployment-owned settings cannot be edited; use credentials reset for access"
            )
        candidate = edit_ini(before, changes)
        return self._backend(selected).configure(
            selected, candidate, expected_text=before, apply=apply
        )

    def credentials(
        self,
        instance: str | Path | Instance | None = None,
        *,
        password: str | None = None,
        username: str = "admin",
    ) -> OperationResult:
        selected = self.resolve(instance)
        return self._backend(selected).credentials(selected, password, username)

    def doctor(
        self,
        instance: str | Path | Instance | None = None,
        *,
        check_http: bool = False,
        deep: bool = False,
        skip_network: bool = False,
    ) -> OperationResult:
        selected = self.resolve(instance)
        spec = selected.spec
        backend = self._backend(selected)
        state = backend.observe(selected)
        checks = {
            "manifest": {
                "status": "valid",
                "detail": f"schema {spec.schema}; {spec.backend}; {spec.instance_id}",
            },
            "configuration": {"status": state.config, "detail": str(spec.profile)},
            "runtime": {"status": state.state, "detail": state.detail},
            "files": {
                "status": "available" if spec.files_dir.is_dir() else "missing",
                "detail": str(spec.files_dir),
            },
            "health": {
                "status": "not_checked",
                "detail": "authenticated HTTP check was not requested",
            },
        }
        storage_details: dict[str, object] = {}
        if spec.backend == "docker":
            storage = cast("ComposeBackend", backend).state_storage(spec)
            volume = self.runner.run(("docker", "volume", "inspect", storage["name"]))
            checks["state_storage"] = {
                "status": "available" if volume.returncode == 0 else "missing",
                "detail": "Docker volume " + storage["name"] + "; runtime root /data",
            }
            storage_details["state_storage"] = storage
        health = "not_checked"
        if (check_http or deep) and not skip_network and state.running:
            if spec.backend == "native":
                healthy = cast("NativeBackend", backend)._health(spec)
            else:
                # Uses the exact compiled Compose health command and its secret
                # mount, without exposing credentials through docker argv.
                result = self.runner.run(
                    (
                        *cast("ComposeBackend", backend)._prefix(selected),
                        "exec",
                        "-T",
                        "xferry",
                        "python",
                        "-c",
                        "from pathlib import Path; from xferry.settings import load_settings_file; "
                        "from xferry.management.service import _endpoint; from "
                        "xferry.management.health import authenticated_ping; "
                        "s=load_settings_file('/etc/xferry/xferry.ini'); "
                        "u,p=Path('/run/secrets/xferry_auth').read_text().strip().split(':',1); "
                        "raise SystemExit(0 if authenticated_ping(_endpoint(s),u,p,4).ok else 1)",
                    )
                )
                healthy = result.returncode == 0
            health = "healthy" if healthy else "unhealthy"
            checks["health"] = {
                "status": health,
                "detail": "authenticated health check passed"
                if healthy
                else "authenticated health check failed",
            }
        from dataclasses import replace

        state = replace(state, health=health)
        code = (
            1
            if state.state in {"broken", "incomplete"}
            or health == "unhealthy"
            or checks["files"]["status"] == "missing"
            or checks.get("state_storage", {}).get("status") == "missing"
            else 0
        )
        return OperationResult(
            code,
            f"{spec.backend.capitalize()} diagnostics completed.",
            details={"checks": checks, **storage_details},
            state=state,
        )

    def setup(
        self,
        *,
        backend: str = "native",
        instance_id: str | None = None,
        version: str | None = None,
        files_dir: str | Path | None = None,
        access: str = "public",
        domain: str | None = None,
        public_ip: str | None = None,
        email: str | None = None,
        firewall: bool | None = None,
        dry_run: bool = False,
        output: str | Path | None = None,
        resources: ResourceOverrides | None = None,
        image: str | None = None,
    ) -> OperationResult:
        from .versions import (
            MIN_DEPLOYMENT_RELEASE,
            compare_release_versions,
            is_supported_release_version,
        )

        if version is not None and (
            not is_supported_release_version(version)
            or compare_release_versions(version, MIN_DEPLOYMENT_RELEASE) < 0
        ):
            return OperationResult(
                2,
                f"New deployments require release {MIN_DEPLOYMENT_RELEASE} or "
                f"later; legacy state was not changed.",
            )
        if backend not in {"native", "docker"}:
            raise ValueError("setup backend must be native or docker")
        if image is not None:
            if backend != "docker" or version is not None:
                raise ValueError(
                    "an explicit digest image requires Docker and cannot be combined "
                    "with a release version"
                )
            import re

            if not re.fullmatch(r"[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}", image):
                raise ValueError("explicit image must use REPOSITORY@sha256:DIGEST")
        if instance_id is not None:
            selected = self.resolve(instance_id)
            if selected.backend != backend:
                raise ValueError("selected instance belongs to another backend")
            if backend == "native":
                cast("NativeBackend", self._backend(selected))._validate(selected)
            if backend == "docker":
                return self.operate("start", selected, dry_run=dry_run)
        if backend == "docker":
            from .compose_backend import ComposeBackend

            adapter = self._compose_backend or ComposeBackend(self.runner)
            self._compose_backend = adapter
            return adapter.setup(
                Path(output) if output else user_data_dir() / "deployment",
                files_dir=Path(files_dir) if files_dir else None,
                version=version,
                access=access,
                domain=domain,
                public_ip=public_ip,
                email=email,
                dry_run=dry_run,
                image=image,
            )
        import sys

        if sys.platform != "linux":
            return OperationResult(
                4,
                "Native setup requires a supported Linux/systemd host; choose "
                "Docker or foreground run.",
            )
        if not dry_run and self.effective_uid() != 0:
            return OperationResult(3, "Native setup requires root.")
        from xferry.config import __version__

        from .managed_state import has_retained_state, has_unsupported_managed_state
        from .model import ManagedLayout, ResourceOverrides, SetupMode, SetupOptions
        from .planning import build_setup_plan
        from .platform import detect_host_facts
        from .setup import SetupExecutor, default_setup_preflight, preflight_result

        layout = self.layout or ManagedLayout()
        if has_unsupported_managed_state(layout):
            return OperationResult(
                2,
                "Unsupported or ambiguous native state was preserved; remove it "
                "with its original tooling before a clean setup.",
            )
        retained = has_retained_state(layout)
        if retained:
            if dry_run:
                return OperationResult(
                    0,
                    "Retained native deployment validated; setup will reinstall its "
                    "runtime and resume.",
                )
            if not layout.current_executable.is_file():
                from .bootstrap import install_release

                installed_retained = install_release(version or __version__, runner=self.runner)
                if installed_retained.exit_code:
                    return OperationResult(installed_retained.exit_code, installed_retained.message)
            resumed = SetupExecutor(runner=self.runner, effective_uid=self.effective_uid).resume(
                layout
            )
            if resumed.exit_code == 0:
                register_instance(layout.config_file.parent / "deployment.json")
            return self._result(resumed)
        if (layout.config_file.parent / "deployment.json").exists():
            existing = self.resolve(layout.config_file.parent / "deployment.json")
            observed = self.observe(existing)
            if observed.state in {"running", "stopped"}:
                return OperationResult(
                    0,
                    "Native deployment already configured; use config, start or restart.",
                    state=observed,
                )
            if dry_run:
                return OperationResult(
                    0,
                    "Native recovery will validate retained profile and credentials "
                    "before activation.",
                    state=observed,
                )
            recovered = SetupExecutor(runner=self.runner, effective_uid=self.effective_uid).resume(
                layout, require_retained=False
            )
            return self._result(recovered)
        ensure_dedicated_files_folder(Path(files_dir) if files_dir else layout.data_root / "files")
        mode = (
            SetupMode.PRIVATE
            if access in {"private", "lab"}
            else SetupMode.DOMAIN
            if domain
            else SetupMode.SSLIP
        )
        facts = detect_host_facts(data_path=Path(files_dir) if files_dir else layout.data_root)
        plan = build_setup_plan(
            SetupOptions(
                mode=mode,
                domain=domain,
                public_ip=public_ip,
                email=email,
                firewall_answer=firewall,
                resources=resources or ResourceOverrides(),
                layout=layout,
                files_dir=Path(files_dir) if files_dir else None,
            ),
            facts,
        )
        preflight = default_setup_preflight(plan, self.runner, interactive=False)
        blockers = tuple(
            failure for failure in preflight.failures if failure.code != "executable-missing"
        )
        if blockers:
            from dataclasses import replace

            preflight_result_value = self._result(
                preflight_result(replace(preflight, failures=blockers))
            )
            if any(failure.code == "firewall-consent-required" for failure in blockers):
                return replace(
                    preflight_result_value,
                    details={
                        **preflight_result_value.details,
                        "firewall_consent_required": True,
                        "firewall_ports": list(preflight.required_bind_ports),
                    },
                )
            return preflight_result_value
        if dry_run:
            return OperationResult(
                0,
                "Native setup validated; no changes made.",
                details={
                    "files_dir": str(plan.files_dir),
                    "port": plan.port,
                    "version": version or __version__,
                    "runtime_install_required": not layout.current_executable.is_file(),
                },
                plan=OperationPlan(
                    "setup",
                    steps=(
                        "verify signed runtime",
                        "create account and grant directory ACL",
                        "write host profile and compiled runtime",
                        "start and verify authenticated health",
                    ),
                    retains=(str(plan.files_dir),),
                ),
            )
        if not layout.current_executable.is_file():
            from .bootstrap import install_release

            installed = install_release(version or __version__, runner=self.runner)
            if installed.exit_code:
                return OperationResult(installed.exit_code, installed.message)
        return self.setup_native(plan)

    def setup_native(
        self, plan: SetupPlan, *, executor: SetupExecutor | None = None
    ) -> OperationResult:
        from .setup import SetupExecutor

        with dedicated_files_folder(plan.files_dir or plan.layout.data_root / "files"):
            result = (
                executor or SetupExecutor(runner=self.runner, effective_uid=self.effective_uid)
            ).apply(plan)
            if result.exit_code == 0:
                path = plan.layout.config_file.parent / "deployment.json"
                register_instance(path)
                spec = load_manifest(path)
                return OperationResult(
                    0,
                    result.message,
                    details={"instance_id": spec.instance_id, "files_dir": str(spec.files_dir)},
                    credentials=result.credentials,
                    url=result.credentials.url if result.credentials else None,
                )
            return self._result(result)

    def setup_compose(self, output: Path, **options: Any) -> OperationResult:
        return self.setup(backend="docker", output=output, **options)

    @staticmethod
    def _result(result: SetupResult | CredentialsResult) -> OperationResult:
        return OperationResult(
            result.exit_code,
            result.message,
            details={
                "code": getattr(result, "code", None),
                "detail": getattr(result, "detail", ""),
                "next_actions": list(getattr(result, "next_actions", ())),
            },
            credentials=getattr(result, "credentials", None),
        )


def default_application() -> ManagementApplication:
    return ManagementApplication()
