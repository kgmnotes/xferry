"""
Main HTTP server with custom method support.
"""

from __future__ import annotations

import gzip
import ipaddress
import json
import logging
import secrets
import socket
import ssl
import sys
import threading
import time
from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .advanced_sessions import AdvancedSessionPrincipal, AdvancedSessionStore
from .config import HIDDEN_FILES, __version__
from .extensions import HandlerContext, PluginMethodSpec, PluginSpec, coerce_plugin_specs
from .features import (
    core_method_spec,
    cors_methods,
    registry_methods,
    websocket_route_enabled,
)
from .handlers import HandlerMixin
from .handlers.context import HandlerRuntimeContext, SmuggleTempCoordinator
from .handlers.registry import Handler
from .http import HTTPRequest, HTTPResponse, error_response
from .http.io import BodyMemoryBudget, RequestReceiveResult
from .http.io import receive_request_result as _receive_request_result_io
from .lifecycle import ServerLifecycle
from .metrics import MetricsCollector
from .notepad_service import DEFAULT_MAX_NOTES, NoteStoragePolicy
from .request_pipeline import RequestPipeline, ResponseBuildArgs
from .security.auth import AuthRateLimiter, BasicAuthenticator, generate_random_credentials
from .security.tls_manager import TLSManager
from .server_config import ServerConfig, resolve_server_config, validate_plugin_specs
from .smuggle.policy import SmuggleTempPolicy
from .storage import UploadStoragePolicy, UploadStorageService
from .websocket_runtime import WebSocketRuntime

# Logging setup
logger = logging.getLogger("xferry")
_FETCH_METADATA_SAME_ORIGIN_VALUES = frozenset({"same-origin", "none"})
_ADVANCED_SESSION_COLLECTION_PATH = "/_xferry/advanced-sessions"
_ADVANCED_SESSION_CURRENT_PATH = "/_xferry/advanced-sessions/current"
_ADVANCED_SESSION_CONTROL_TARGETS = frozenset(
    {_ADVANCED_SESSION_COLLECTION_PATH, _ADVANCED_SESSION_CURRENT_PATH}
)
_ADVANCED_SESSION_HEADER = "X-XFerry-Advanced-Session"
_DEFAULT_ERROR_CODES = {
    400: "bad_request",
    401: "authentication_required",
    403: "forbidden",
    404: "resource_not_found",
    405: "method_not_allowed",
    409: "conflict",
    413: "payload_too_large",
    415: "unsupported_media_type",
    429: "rate_limited",
    500: "internal_error",
    501: "feature_unavailable",
    503: "server_busy",
    507: "storage_quota_exceeded",
}


class _JSONLogFormatter(logging.Formatter):
    """Structured JSON log formatter."""

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "msg": record.getMessage(),
        }
        if record.exc_info and record.exc_info[1]:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, ensure_ascii=False)


class XFerryServer(HandlerMixin):
    """HTTP server with custom method support."""

    # Hidden files not accessible via GET
    HIDDEN_FILES = HIDDEN_FILES

    def __init__(self, config: ServerConfig):
        config = resolve_server_config(config)
        loaded_plugins = coerce_plugin_specs(
            config.plugins.direct,
            config.plugins.module_entries,
        )
        validate_plugin_specs(loaded_plugins, override_core=config.plugins.override_core)
        limits = config.limits
        websocket = config.websocket
        tls_config = config.tls
        auth_config = config.auth
        logging_config = config.logging
        plugin_config = config.plugins

        self.host = config.host
        self.port = config.port
        self.root_dir = Path(config.root_dir)
        self.max_upload_size = limits.max_upload_size
        self.upload_storage_policy = UploadStoragePolicy(
            max_total_bytes=limits.upload_storage_limit,
            max_file_count=limits.upload_file_limit,
            reserved_free_bytes=limits.upload_reserved_free_space,
        )
        self.note_storage_policy = NoteStoragePolicy(
            max_total_bytes=limits.note_storage_limit,
            max_note_count=limits.note_count_limit,
            max_listed_notes=limits.note_count_limit or DEFAULT_MAX_NOTES,
        )
        self.smuggle_temp_policy = SmuggleTempPolicy(
            max_age_seconds=limits.smuggle_temp_max_age,
            max_file_count=limits.smuggle_temp_file_limit,
            max_total_bytes=limits.smuggle_temp_storage_limit,
        )
        self.max_header_size = limits.max_header_size
        self.max_workers = limits.max_workers
        assert limits.body_memory_budget is not None
        self.body_memory_budget = limits.body_memory_budget
        self._body_memory_budget = BodyMemoryBudget(self.body_memory_budget)
        self.body_idle_timeout = limits.body_idle_timeout
        self.body_timeout = limits.body_timeout
        self.body_min_rate = limits.body_min_rate
        self.stream_send_idle_timeout = limits.stream_send_idle_timeout
        self.stream_send_timeout = limits.stream_send_timeout
        assert websocket.max_connections is not None
        self.max_websocket_connections = websocket.max_connections
        self.websocket_frame_idle_timeout = websocket.frame_idle_timeout
        self.debug = logging_config.debug
        self.open_browser = logging_config.open_browser
        self.json_log = logging_config.json_log
        self.cors_origin = config.cors_origin
        self.cors_origins = config.cors_origins
        self.public_direct = config.public_direct
        self.runtime_posture = config.runtime_posture

        # TLS settings (delegated to TLSManager; these fields stay as read-only
        # views used by status printing and request handling).
        self._tls = TLSManager(
            enabled=tls_config.enabled,
            cert_file=str(tls_config.cert_file) if tls_config.cert_file else None,
            key_file=str(tls_config.key_file) if tls_config.key_file else None,
            letsencrypt=tls_config.letsencrypt,
            domain=tls_config.domain,
            email=tls_config.email,
            host=config.host,
            sslip=tls_config.sslip,
            public_ip=tls_config.public_ip,
            acme_staging=tls_config.acme_staging,
            acme_server=tls_config.acme_server,
            acme_http_address=tls_config.acme_http_address,
            acme_http_port=tls_config.acme_http_port,
        )
        self.letsencrypt = tls_config.letsencrypt
        self.domain = tls_config.domain
        self.email = tls_config.email
        self.sslip = tls_config.sslip
        self.public_ip = tls_config.public_ip
        self.acme_staging = tls_config.acme_staging
        self.acme_server = tls_config.acme_server
        self.acme_http_address = tls_config.acme_http_address
        self.acme_http_port = tls_config.acme_http_port

        # Temporary SMUGGLE files (deleted after serving)
        self._temp_smuggle_files: set[str] = set()
        self._smuggle_lock = threading.Lock()

        # Notes lock for thread-safe notepad writes
        self._notes_lock = threading.Lock()

        # ECDH key manager for Secure Notepad v2
        self._ecdh_manager = None
        try:
            from .security.keys import ECDHKeyManager

            self._ecdh_manager = ECDHKeyManager()
        except (ImportError, RuntimeError):
            pass

        # In-memory metrics
        self._metrics = MetricsCollector()
        self.advanced_session_store = AdvancedSessionStore()

        self._lifecycle = ServerLifecycle(
            host=self.host,
            port=self.port,
            max_workers=self.max_workers,
            tls_manager=self._tls,
            metrics=self._metrics,
            handle_client=self._handle_client,
            reject_overloaded=self._reject_overloaded_connection,
            on_started=self._on_runtime_started,
            on_shutdown=self._on_runtime_shutdown,
            on_interrupted=lambda: print("\nShutting down..."),
            setup_tls=lambda: self._setup_tls(),
            cleanup_tls=lambda: self._cleanup_temp_files(),
            socket_factory=lambda: socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM,
            ),
            executor_factory=lambda workers: ThreadPoolExecutor(max_workers=workers),
        )
        self._websocket_runtime = WebSocketRuntime(
            max_connections=self.max_websocket_connections,
            frame_idle_timeout=self.websocket_frame_idle_timeout,
            idle_timeout=self.WEBSOCKET_IDLE_TIMEOUT,
            metrics=self._metrics,
            is_running=lambda: self.running,
            handle_message=self._handle_ws_message,
            record_timeout=self._record_timeout,
        )

        # Basic Auth
        self.authenticator: BasicAuthenticator | None = None
        self._rate_limiter: AuthRateLimiter | None = None
        self._setup_auth(
            auth_config.auth,
            str(auth_config.auth_file) if auth_config.auth_file else None,
        )

        # Logging setup
        self._setup_logging(logging_config.quiet)

        self.root_dir.mkdir(parents=True, exist_ok=True)

        # Directory for uploaded files
        self.upload_dir = self.root_dir / "uploads"
        self.upload_dir.mkdir(exist_ok=True)
        self.upload_storage = UploadStorageService(
            self.upload_dir,
            self.upload_storage_policy,
            metrics=self._metrics,
        )
        self.handler_context = HandlerRuntimeContext(
            upload_dir=self.upload_dir,
            upload_storage=self.upload_storage,
            metrics=self._metrics,
            smuggle_temp=SmuggleTempCoordinator(
                lock=self._smuggle_lock,
                paths=self._temp_smuggle_files,
            ),
        )

        # Directory for encrypted notepad blobs, kept separate from uploads/.
        self.notes_dir = self.root_dir / "notes"
        self.notes_dir.mkdir(exist_ok=True)
        self._notepad_service = None

        # Clean up stale SMUGGLE files from previous sessions
        self._cleanup_old_smuggle_files()

        self.plugin_methods: dict[str, str] = {}
        self._plugin_method_policies: dict[str, PluginMethodSpec] = {}
        self.method_handlers = self.build_method_handlers()
        self._register_plugins(
            plugins=loaded_plugins,
            plugin_modules=(),
            override_core=plugin_config.override_core,
            allow_public_direct=plugin_config.allow_public_direct,
        )
        self._request_pipeline = RequestPipeline(self)

    def _register_plugins(
        self,
        *,
        plugins: Sequence[PluginSpec] | None,
        plugin_modules: Sequence[str] | None,
        override_core: bool,
        allow_public_direct: bool,
    ) -> None:
        """Register explicitly enabled plugin HTTP methods."""
        if self.public_direct and (plugins or plugin_modules) and not allow_public_direct:
            raise ValueError(
                "public_direct disables plugins unless plugins_allow_public_direct is true"
            )

        core_methods = set(registry_methods())
        for plugin in coerce_plugin_specs(plugins, plugin_modules):
            for method_spec in plugin.methods:
                method = method_spec.method
                if method in core_methods and not override_core:
                    raise ValueError(f"plugin method {method} would override a core method")

                context = HandlerContext(
                    server=self,
                    plugin_name=plugin.name,
                )
                self.method_handlers.register(
                    method,
                    self._build_plugin_handler(method_spec, context),
                )
                self.plugin_methods[method] = plugin.name
                self._plugin_method_policies[method] = method_spec

    @staticmethod
    def _build_plugin_handler(
        method_spec: PluginMethodSpec,
        context: HandlerContext,
    ) -> Handler:
        """Wrap a plugin handler in the core registry handler signature."""

        def _handle_plugin(request: HTTPRequest) -> HTTPResponse:
            return method_spec.handler(request, context)

        return _handle_plugin

    def set_authenticator(self, authenticator: BasicAuthenticator | None) -> None:
        """Install an authenticator and keep auth rate limiting in sync."""
        previous_mode_has_authenticator = self.authenticator is not None
        self.authenticator = authenticator
        self._rate_limiter = AuthRateLimiter() if authenticator else None
        if previous_mode_has_authenticator != (authenticator is not None):
            self.advanced_session_store.invalidate_all()

    def _setup_auth(self, auth: str | None, auth_file: str | None = None) -> None:
        """Set up Basic Auth."""
        if auth_file == "":
            raise ValueError("--auth-file value must not be empty")
        if auth and auth_file:
            raise ValueError("--auth and --auth-file cannot be combined")

        if auth_file:
            auth = self._read_auth_file(auth_file)

        if not auth:
            return

        if auth == "random":
            username, password = generate_random_credentials()
            self.set_authenticator(BasicAuthenticator({username: password}))
            self._print_generated_credentials(username, password)
        elif ":" in auth:
            username, password = auth.split(":", 1)
            self.set_authenticator(BasicAuthenticator({username: password}))
        else:
            # Username only, password = random
            password = secrets.token_urlsafe(16)
            self.set_authenticator(BasicAuthenticator({auth: password}))
            self._print_generated_credentials(auth, password)

    @staticmethod
    def _read_auth_file(path: str) -> str:
        """Read a single user:password credential line from a file."""
        auth_path = Path(path)
        try:
            raw_value = auth_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            raise ValueError("auth file does not exist") from None
        except OSError:
            raise ValueError("auth file could not be read") from None
        except UnicodeDecodeError:
            raise ValueError("auth file must be UTF-8 text") from None

        if raw_value.endswith("\r\n"):
            value = raw_value[:-2]
        elif raw_value.endswith(("\r", "\n")):
            value = raw_value[:-1]
        else:
            value = raw_value
        if not value or "\n" in value or "\r" in value:
            raise ValueError("auth file must contain exactly one user:password line")

        username, separator, password = value.partition(":")
        if not separator or not username or not password:
            raise ValueError("auth file must contain exactly one user:password line")
        return value

    @staticmethod
    def _print_generated_credentials(username: str, password: str) -> None:
        """Print generated credentials only for an interactive terminal."""
        if not sys.stdout.isatty():
            raise RuntimeError(
                "--auth random refuses to print generated credentials to non-interactive "
                "stdout; pass --auth-file or explicit --auth user:password instead."
            )
        print("\n[AUTH] Generated credentials:")
        print(f"  Username: {username}")
        print(f"  Password: {password}")

    def _setup_logging(self, quiet: bool) -> None:
        """Set up logging."""
        if self.debug:
            level = logging.DEBUG
        else:
            level = logging.WARNING if quiet else logging.INFO

        handler = logging.StreamHandler()
        if self.json_log:
            handler.setFormatter(_JSONLogFormatter())
        else:
            handler.setFormatter(
                logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
            )
        logger.handlers = [handler]
        logger.setLevel(level)

    def _setup_tls(self) -> None:
        """Set up the TLS context (delegated to TLSManager)."""
        self._tls.setup()

    @property
    def tls_enabled(self) -> bool:
        return self._tls.enabled

    @property
    def ssl_context(self) -> ssl.SSLContext | None:
        return self._tls.ssl_context

    @property
    def cert_file(self) -> str | None:
        return self._tls.cert_file

    @property
    def key_file(self) -> str | None:
        return self._tls.key_file

    @property
    def _temp_cert_files(self) -> list[str]:
        return self._tls.temp_cert_files

    def _record_metric(
        self,
        status_code: int,
        response_size: int,
        *,
        error: bool = False,
    ) -> None:
        """Record request metrics (thread-safe)."""
        self._metrics.record(status_code, response_size, error=error)

    def _record_bytes_received(self, byte_count: int) -> None:
        """Record client request bytes received by the server."""
        self._metrics.record_bytes_received(byte_count)

    def _record_request_latency(self, duration_ms: float) -> None:
        """Record elapsed request processing time."""
        self._metrics.record_request_latency(duration_ms)

    def _record_receive_rejection(self, reason: str) -> None:
        """Record a receive-layer rejection reason."""
        self._metrics.record_receive_rejection(reason)

    def _record_timeout(self, reason: str) -> None:
        """Record a timeout signal."""
        self._metrics.record_timeout(reason)

    def _record_response_stream_abort(self, reason: str) -> None:
        """Record an aborted streamed response."""
        self._metrics.record_response_stream_abort(reason)

    def _record_worker_exception(self, source: str, exc: BaseException) -> None:
        """Record an exception that happened in worker-owned execution."""
        self._metrics.record_worker_exception(source, exc)

    def get_metrics(self) -> dict[str, object]:
        """Return current server metrics snapshot."""
        scan_started = time.perf_counter()
        upload_usage = self.upload_storage.current_usage()
        self._metrics.record_scan_observation(
            "storage_snapshot",
            (time.perf_counter() - scan_started) * 1000,
            items=upload_usage.file_count,
        )

        self._get_notepad_service().current_usage()

        scan_started = time.perf_counter()
        smuggle_usage = self.get_smuggle_temp_usage()
        self._metrics.record_scan_observation(
            "storage_snapshot",
            (time.perf_counter() - scan_started) * 1000,
            items=smuggle_usage.file_count,
        )

        metrics = self._metrics.snapshot()
        metrics["body_memory"] = self._body_memory_budget.snapshot()
        return metrics

    def _try_acquire_request_admission(self, *, wait_timeout: float = 0.0) -> bool:
        """Compatibility delegate to lifecycle-owned request admission."""
        return self._lifecycle.acquire_legacy_admission(wait_timeout=wait_timeout)

    def _release_request_admission(self) -> None:
        """Release a previously acquired request admission slot."""
        self._lifecycle.release_legacy_admission()

    def _reject_overloaded_connection(self, client_socket: Any) -> None:
        """Reject a connection when no worker admission slot is available."""
        if self.tls_enabled:
            client_socket.close()
            return

        response = self._build_error_response(503, "Server busy", code="server_busy")
        try:
            client_socket.sendall(response.build(keep_alive=False))
        except Exception:
            pass
        finally:
            client_socket.close()

    def _handle_admitted_client(
        self,
        client_socket: Any,
        client_address: tuple[str, int],
    ) -> None:
        """Handle a client and always release its request admission slot."""
        self._lifecycle.handle_legacy_admitted_client(
            client_socket,
            client_address,
            self._handle_client,
        )

    def _release_cancelled_admission(
        self,
        future: object,
        client_socket: Any,
    ) -> None:
        """Release admission for work canceled before the worker wrapper starts."""
        self._lifecycle.release_legacy_cancelled(future, client_socket)

    def _finalize_worker_future(
        self,
        future: object,
        client_socket: Any,
        client_address: tuple[str, int],
    ) -> None:
        """Observe worker completion so cancellations and exceptions are visible."""
        self._lifecycle.finalize_legacy_future(
            future,
            client_socket,
            client_address,
        )

    def _try_acquire_websocket_slot(self) -> bool:
        """Return True if a WebSocket connection can enter the active set."""
        return self._websocket_runtime.try_acquire_legacy_slot()

    def _release_websocket_slot(self) -> None:
        """Release a previously acquired WebSocket connection slot."""
        self._websocket_runtime.release_legacy_slot()

    # Content types eligible for gzip compression
    _COMPRESSIBLE_TYPES = (
        "text/",
        "application/json",
        "application/javascript",
        "application/xml",
        "application/xhtml+xml",
        "image/svg+xml",
    )

    def _maybe_gzip_response(self, response: HTTPResponse) -> None:
        """Compress the response body with gzip if appropriate."""
        content_type = response.headers.get("Content-Type", "")
        if not any(content_type.startswith(ct) for ct in self._COMPRESSIBLE_TYPES):
            return

        # Keep streamed files streamed; gzip here would require buffering the
        # entire file before sending it.
        if response.stream_path is not None:
            return

        # For body responses
        if len(response.body) < 256:
            return
        compressed = gzip.compress(response.body)
        if len(compressed) >= len(response.body):
            return
        response.body = compressed
        response.set_header("Content-Length", str(len(compressed)))
        response.set_header("Content-Encoding", "gzip")
        response.set_header("Vary", "Accept-Encoding")

    def _cleanup_temp_files(self) -> None:
        """Clean up temporary certificate files."""
        self._tls.cleanup()

    def _cleanup_old_smuggle_files(self) -> None:
        """Clean up stale SMUGGLE files from previous sessions."""
        count = self.cleanup_smuggle_temp_artifacts(remove_all=True)
        if count > 0:
            logger.info(f"Cleaned up {count} stale SMUGGLE files")

    def start(self) -> None:
        """Delegate the blocking server run to the lifecycle owner."""
        self._lifecycle.start()

    def _on_runtime_started(self) -> None:
        """Render facade-owned operator output after the runtime is listening."""
        self.domain = self._tls.domain
        self.public_ip = self._tls.public_ip

        if self.debug:
            logger.debug("Debug logging enabled")

        protocol = "https" if self.tls_enabled else "http"
        display_host = self.domain if self.sslip and self.domain else self.host
        url = f"{protocol}://{display_host}:{self.port}"

        print("=" * 60)
        print(f"  xferry v{__version__}")
        print(f"  {url}")
        if self.runtime_posture is not None:
            print()
            for line in self.runtime_posture.render_lines(effective_url=url):
                print(f"  {line}")
        print()
        print(f"  Root directory: {self.root_dir}")
        print(f"  File access: uploads/ only ({self.upload_dir})")
        print(f"  Notepad storage: notes/ ({self.notes_dir})")
        print(f"  Max upload request: {self.max_upload_size // (1024 * 1024)} MB")
        print(f"  Body memory budget: {self.body_memory_budget // (1024 * 1024)} MB")
        print(f"  Body idle timeout: {self.body_idle_timeout or 'disabled'} s")
        print(f"  Body deadline: {self.body_timeout or 'disabled'} s")
        print(f"  Body minimum rate: {self.body_min_rate or 'disabled'} B/s")
        print(f"  Upload storage: {self.upload_storage.describe_limit()}")
        print(f"  Notepad limits: {self.note_storage_policy.describe_limit()}")
        print(f"  Max headers: {self.max_header_size // 1024} KiB")
        print(f"  WebSocket connections: {self.max_websocket_connections}")
        print(f"  WebSocket incomplete-frame timeout: {self.websocket_frame_idle_timeout:g} s")
        print(f"  Methods: {', '.join(self.method_handlers.keys())}")

        if self.tls_enabled:
            print(f"\n  [TLS]     certificate: {self._tls.describe()}")

        if self.authenticator:
            print("  [AUTH]    Basic Auth enabled")

        print("\n  Ctrl+C to stop")
        print("=" * 60)

        if self.open_browser:
            import webbrowser

            webbrowser.open(url)

    def _on_runtime_shutdown(self) -> None:
        """Clean facade-owned application artifacts after runtime resources close."""
        self.handler_context.smuggle_temp.remove_all_registered()
        print("Server stopped")

    def stop(self) -> None:
        """Delegate termination to the lifecycle owner."""
        self._lifecycle.stop()

    @property
    def socket(self) -> Any | None:
        """Compatibility view of the lifecycle-owned listener."""
        return self._lifecycle.listener

    @property
    def running(self) -> bool:
        """Compatibility view of lifecycle running state."""
        return self._lifecycle.running

    @running.setter
    def running(self, value: bool) -> None:
        self._lifecycle.running = value

    # Keep-alive settings
    KEEP_ALIVE_TIMEOUT: int = 15  # seconds idle between requests
    KEEP_ALIVE_MAX: int = 100  # max requests per connection
    WEBSOCKET_IDLE_TIMEOUT: float = 60.0  # seconds idle before a keepalive ping
    REQUEST_ADMISSION_WAIT_TIMEOUT: float = 0.05  # seconds to reuse just-freed capacity

    def _should_keep_alive(self, request: HTTPRequest) -> bool:
        """Determine whether to keep the connection alive after this request."""
        conn_header = request.headers.get("connection", "").lower()
        if conn_header == "close":
            return False

        # HTTP/1.1 defaults to keep-alive; HTTP/1.0 defaults to close
        if request.http_version == "HTTP/1.1":
            return conn_header != "close"
        return conn_header == "keep-alive"

    def _handle_client(
        self,
        client_socket: Any,
        client_address: tuple[str, int],
    ) -> None:
        """Handle a client connection (with keep-alive support)."""
        try:
            # TLS handshake in worker thread (not blocking accept loop)
            if self.tls_enabled and self.ssl_context:
                try:
                    client_socket.settimeout(5.0)
                    client_socket = self.ssl_context.wrap_socket(client_socket, server_side=True)
                except ssl.SSLError as e:
                    logger.debug(f"SSL handshake failed: {e}")
                    client_socket.close()
                    return

            requests_on_conn = 0

            while self.running:
                # For subsequent requests, use keep-alive idle timeout
                idle_timeout = self.KEEP_ALIVE_TIMEOUT if requests_on_conn > 0 else None

                received = self._receive_request_result(client_socket, idle_timeout=idle_timeout)
                if not received.data:
                    if received.rejection_reason == "body_too_large":
                        max_mb = self.max_upload_size // (1024 * 1024)
                        self._send_receive_rejection_response(
                            client_socket,
                            413,
                            f"Payload too large. Max size: {max_mb} MB",
                        )
                    elif received.rejection_reason == "body_memory_budget_exceeded":
                        self._send_receive_rejection_response(
                            client_socket,
                            503,
                            "Request body memory budget exceeded",
                        )
                    break

                try:
                    self._record_bytes_received(len(received.data))

                    requests_on_conn += 1
                    keep_alive = self._process_request(
                        received.data,
                        client_socket,
                        client_address,
                        requests_on_conn,
                    )
                finally:
                    received.release_body_reservation()
                if not keep_alive:
                    break
        except Exception as exc:
            self._record_worker_exception("handle_client", exc)
            logger.exception("Client worker failed for %s:%d", client_address[0], client_address[1])
        finally:
            client_socket.close()

    def _authenticate_request(
        self,
        request: HTTPRequest,
        client_address: tuple[str, int],
    ) -> HTTPResponse | None:
        """Check Basic Auth and rate limiting.

        Returns an error HTTPResponse to send back, or None if auth passed.
        """
        if not self.authenticator:
            return None

        ip = client_address[0]

        if self._rate_limiter and self._rate_limiter.is_blocked(ip):
            logger.warning(f"Rate limited: {ip}")
            return self._build_error_response(
                429,
                "Too Many Requests",
                code="rate_limited",
                field="Authorization",
            )

        auth_header = request.headers.get("authorization")
        verified_principal = self.authenticator.verify(auth_header)
        if verified_principal is None:
            if self._rate_limiter:
                self._rate_limiter.record_failure(ip)
            logger.warning(f"Auth rejected: {ip}")
            response = self._build_error_response(
                401,
                "Unauthorized",
                code="authentication_required",
                field="Authorization",
            )
            response.set_header(
                "WWW-Authenticate",
                self.authenticator.get_www_authenticate_header(),
            )
            return response

        if self._rate_limiter:
            self._rate_limiter.reset(ip)
        request.set_verified_principal(verified_principal)
        return None

    def _send_response(
        self,
        response: HTTPResponse,
        client_socket: Any,
        _bld: ResponseBuildArgs,
    ) -> int:
        """Send *response* to *client_socket* and return bytes sent.

        Handles both streamed (file) and buffered (body) responses.
        For streamed responses, ``_bld`` is overridden to close the connection.
        """

        stream_deadline = (
            time.monotonic() + self.stream_send_timeout
            if self.stream_send_timeout is not None
            else None
        )

        def sendall_with_stream_deadline(payload: bytes) -> None:
            timeout = self.stream_send_idle_timeout
            if stream_deadline is not None:
                remaining = stream_deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("stream response send deadline exceeded")
                timeout = min(timeout, max(0.001, remaining))
            client_socket.settimeout(timeout)
            client_socket.sendall(payload)

        try:
            previous_timeout = client_socket.gettimeout()
        except AttributeError:
            previous_timeout = None
        try:
            if response.stream_path is not None:
                _bld_close: ResponseBuildArgs = {**_bld, "keep_alive": False}
                bytes_sent = 0
                header_bytes = response.build_headers(**_bld_close)
                try:
                    sendall_with_stream_deadline(header_bytes)
                except TimeoutError:
                    self._record_timeout("response_stream_timeout")
                    self._record_response_stream_abort("timeout")
                    logger.warning("Streamed response aborted before headers were sent")
                    return bytes_sent
                bytes_sent = len(header_bytes)
                with response.stream_path.open("rb") as f:
                    while True:
                        chunk = f.read(65536)
                        if not chunk:
                            break
                        try:
                            sendall_with_stream_deadline(chunk)
                        except TimeoutError:
                            self._record_timeout("response_stream_timeout")
                            self._record_response_stream_abort("timeout")
                            logger.warning(
                                "Streamed response aborted after %d bytes sent",
                                bytes_sent,
                            )
                            return bytes_sent
                        bytes_sent += len(chunk)
                return bytes_sent

            response_bytes = response.build(**_bld)
            client_socket.sendall(response_bytes)
            return len(response_bytes)
        finally:
            try:
                client_socket.settimeout(previous_timeout)
            except AttributeError:
                pass
            if response.stream_cleanup is not None:
                response.stream_cleanup()
                response.stream_cleanup = None

    def _check_payload_size(self, request: HTTPRequest) -> HTTPResponse | None:
        """Reject requests whose Content-Length exceeds the configured cap."""
        try:
            content_length = int(request.headers.get("content-length", 0))
        except ValueError:
            return None
        if content_length <= self.max_upload_size:
            return None

        max_mb = self.max_upload_size // (1024 * 1024)
        return self._build_error_response(
            413,
            f"Payload too large. Max size: {max_mb} MB",
            code="payload_too_large",
        )

    def _send_receive_rejection_response(
        self,
        client_socket: Any,
        status: int,
        message: str,
    ) -> None:
        """Send a stable HTTP error for receive-layer rejections that support it."""
        response = self._build_error_response(
            status,
            message,
            code="server_busy" if status == 503 else None,
        )
        try:
            payload = response.build(keep_alive=False)
            client_socket.sendall(payload)
            self._record_metric(status, len(payload), error=status >= 500)
        except Exception:
            pass

    def _resolve_keep_alive(
        self,
        request: HTTPRequest,
        request_num: int,
    ) -> tuple[bool, int]:
        """Return ``(use_keep_alive, remaining_requests)`` for this connection."""
        want_keep_alive = self._should_keep_alive(request)
        remaining = self.KEEP_ALIVE_MAX - request_num
        return want_keep_alive and remaining > 0, remaining

    def _post_process_response(
        self,
        request: HTTPRequest,
        response: HTTPResponse,
        request_id: str,
    ) -> None:
        """Apply response decorations."""
        response.set_header("X-Request-Id", request_id)
        no_gzip_headers = ("x-xferry-no-gzip", "x-exphttp-no-gzip")
        if any(
            request.headers.get(header, "").lower() in {"1", "true", "yes"}
            for header in no_gzip_headers
        ):
            return
        if "gzip" in request.headers.get("accept-encoding", ""):
            self._maybe_gzip_response(response)

    def _resolve_cors_origin(self, request: HTTPRequest) -> str | None:
        """Resolve configured CORS origins against the request Origin header."""
        request_origin = request.headers.get("origin")
        if not request_origin or not self.cors_origins:
            return None
        if self.cors_origins == ("*",):
            return "*"
        if request_origin in self.cors_origins:
            return request_origin
        return None

    def _cors_allow_methods_header(self) -> str:
        """Return the CORS allow-methods header value."""
        read_only = self.cors_origins == ("*",)
        methods = list(cors_methods(read_only=read_only))
        for method, policy in self._plugin_method_policies.items():
            if not policy.cors_allowed:
                continue
            if read_only and policy.mutating:
                continue
            methods.append(method)
        return ", ".join(methods)

    def _is_browser_mutation_allowed(self, request: HTTPRequest) -> bool:
        """Allow only same-origin or explicitly configured browser mutations.

        Non-browser clients normally omit both Origin and Sec-Fetch-Site, so
        they keep the documented API behavior.
        """
        if not self._is_browser_protected_mutation(request):
            return True

        origin = request.headers.get("origin")
        if origin:
            if (
                fetch_site := request.headers.get("sec-fetch-site", "").strip().lower()
            ) and fetch_site not in _FETCH_METADATA_SAME_ORIGIN_VALUES:
                return self._is_explicit_cors_origin(origin)
            return self._is_browser_origin_allowed_for_mutation(request, origin)

        fetch_site = request.headers.get("sec-fetch-site", "").strip().lower()
        if not fetch_site:
            return True
        return fetch_site in _FETCH_METADATA_SAME_ORIGIN_VALUES

    def _is_browser_protected_mutation(self, request: HTTPRequest) -> bool:
        """Return True when an HTTP request can change server-side state."""
        if request.advanced_session_dispatch is not None:
            return True
        plugin_policy = self._plugin_method_policies.get(request.method)
        if plugin_policy is not None:
            return plugin_policy.mutating
        spec = core_method_spec(request.method)
        return bool(spec is not None and request.method in self.method_handlers and spec.mutating)

    def _is_advanced_session_control_route(self, request: HTTPRequest) -> bool:
        """Return True for exact 7C advanced-session control request targets."""
        return request.raw_target in _ADVANCED_SESSION_CONTROL_TARGETS

    def _authorize_advanced_session_control(
        self,
        request: HTTPRequest,
        _client_address: tuple[str, int],
    ) -> HTTPResponse | None:
        """Apply peer and strict browser policy after the single auth pass."""
        if not self._is_advanced_session_control_route(request):
            return None

        if self.authenticator is None:
            direct_peer = request.security_context.direct_peer
            if direct_peer is None or not self._is_loopback_peer(direct_peer[0]):
                return self._control_error(
                    403,
                    "forbidden_peer",
                    "Forbidden peer",
                    field=None,
                )
        elif request.security_context.verified_principal is None:
            response = self._control_error(
                401,
                "authentication_required",
                "Unauthorized",
                field="Authorization",
            )
            response.set_header(
                "WWW-Authenticate",
                self.authenticator.get_www_authenticate_header(),
            )
            return response

        host, header_error = self._advanced_session_control_singleton_header(request, "Host")
        if header_error is not None:
            return header_error
        origin, header_error = self._advanced_session_control_singleton_header(request, "Origin")
        if header_error is not None:
            return header_error
        fetch_site, header_error = self._advanced_session_control_singleton_header(
            request,
            "Sec-Fetch-Site",
        )
        if header_error is not None:
            return header_error

        if origin is not None and not self._is_exact_control_origin(origin, host):
            return self._control_error(
                403,
                "forbidden_origin",
                "Forbidden origin",
                field="Origin",
            )

        if (
            fetch_site is not None
            and fetch_site.strip().lower() not in _FETCH_METADATA_SAME_ORIGIN_VALUES
        ):
            return self._control_error(
                403,
                "forbidden_origin",
                "Forbidden origin",
                field="Sec-Fetch-Site",
            )

        return None

    def _authorize_advanced_session_data_request(
        self,
        request: HTTPRequest,
    ) -> HTTPResponse | None:
        """Apply data-plane peer and browser-origin policy for session-bearing requests."""
        if not (
            request.get_header_values(_ADVANCED_SESSION_HEADER)
            or request.get_raw_header_values(_ADVANCED_SESSION_HEADER)
        ):
            return None

        if self.authenticator is None:
            direct_peer = request.security_context.direct_peer
            if direct_peer is None or not self._is_loopback_peer(direct_peer[0]):
                return self._control_error(
                    403,
                    "forbidden_peer",
                    "Forbidden peer",
                    field=None,
                )
        elif request.security_context.verified_principal is None:
            response = self._control_error(
                401,
                "authentication_required",
                "Unauthorized",
                field="Authorization",
            )
            response.set_header(
                "WWW-Authenticate",
                self.authenticator.get_www_authenticate_header(),
            )
            return response

        host, header_error = self._advanced_session_control_singleton_header(request, "Host")
        if header_error is not None:
            return header_error
        origin, header_error = self._advanced_session_control_singleton_header(request, "Origin")
        if header_error is not None:
            return header_error
        fetch_site, header_error = self._advanced_session_control_singleton_header(
            request,
            "Sec-Fetch-Site",
        )
        if header_error is not None:
            return header_error

        fetch_site_value = fetch_site.strip().lower() if fetch_site is not None else ""
        if origin is not None:
            if fetch_site_value and fetch_site_value not in _FETCH_METADATA_SAME_ORIGIN_VALUES:
                if self._is_explicit_cors_origin(origin):
                    return None
                return self._control_error(
                    403,
                    "forbidden_origin",
                    "Forbidden origin",
                    field="Sec-Fetch-Site",
                )
            if self._is_exact_control_origin(origin, host) or self._is_explicit_cors_origin(origin):
                return None
            return self._control_error(
                403,
                "forbidden_origin",
                "Forbidden origin",
                field="Origin",
            )

        if fetch_site_value and fetch_site_value not in _FETCH_METADATA_SAME_ORIGIN_VALUES:
            return self._control_error(
                403,
                "forbidden_origin",
                "Forbidden origin",
                field="Sec-Fetch-Site",
            )

        return None

    def _advanced_session_control_singleton_header(
        self,
        request: HTTPRequest,
        header_name: str,
    ) -> tuple[str | None, HTTPResponse | None]:
        values = request.get_header_values(header_name)
        if len(values) > 1:
            return None, self._control_error(
                400,
                "invalid_field",
                "Invalid field",
                field=header_name,
            )
        if not values:
            return None, None
        return values[0], None

    @staticmethod
    def _is_loopback_peer(host: str) -> bool:
        try:
            return ipaddress.ip_address(host).is_loopback
        except ValueError:
            return False

    def _advanced_session_principal(self, request: HTTPRequest) -> AdvancedSessionPrincipal:
        """Bridge the already-verified auth context into the session store principal."""
        if self.authenticator is None:
            return AdvancedSessionPrincipal("no_auth", None)
        principal = request.security_context.verified_principal
        if principal is None:
            raise RuntimeError("advanced session control reached without verified principal")
        return AdvancedSessionPrincipal("basic", principal)

    def _is_exact_control_origin(self, origin: str, host: str | None) -> bool:
        """Strict control-plane origin: exactly effective scheme plus Host."""
        if not host:
            return False
        expected_scheme = "https" if self.tls_enabled else "http"
        return origin == f"{expected_scheme}://{host}"

    @staticmethod
    def _control_error(
        status: int,
        code: str,
        message: str,
        *,
        field: str | None,
        details: Mapping[str, object] | None = None,
    ) -> HTTPResponse:
        return error_response(
            status,
            code,
            message,
            field=field,
            details=details,
            no_store=True,
        )

    def _is_browser_origin_allowed_for_mutation(
        self,
        request: HTTPRequest,
        origin: str,
    ) -> bool:
        """Return True when Origin is same-origin or explicitly CORS-allowed."""
        if self._is_explicit_cors_origin(origin):
            return True
        return self._is_same_http_origin(request, origin)

    def _is_explicit_cors_origin(self, origin: str) -> bool:
        """Return True when origin is a configured non-wildcard trusted origin."""
        return origin != "*" and origin in self.cors_origins

    def _is_same_http_origin(self, request: HTTPRequest, origin: str) -> bool:
        """Compare Origin against the request Host and effective server scheme."""
        host = request.headers.get("host", "")
        if not host:
            return False

        expected_scheme = "https" if self.tls_enabled else "http"
        parsed = urlsplit(origin)
        expected_origin = f"{expected_scheme}://{host}"
        return (
            parsed.scheme.lower() == expected_scheme
            and parsed.netloc.lower() == host.lower()
            and parsed.path in ("", "/")
            and origin.rstrip("/").lower() == expected_origin.lower()
        )

    def _build_error_response(
        self,
        status: int,
        message: str,
        *,
        code: str | None = None,
        field: str | None = None,
        details: Mapping[str, object] | None = None,
        no_store: bool = False,
    ) -> HTTPResponse:
        """Compatibility facade for the canonical error response factory."""
        return error_response(
            status,
            _DEFAULT_ERROR_CODES.get(status, "http_error") if code is None else code,
            message,
            field=field,
            details=details,
            no_store=no_store,
        )

    def _is_websocket_origin_allowed(self, request: HTTPRequest) -> bool:
        """Allow same-origin upgrades by default; cross-origin requires explicit opt-in."""
        origin = request.headers.get("origin", "")
        if not origin:
            return True

        if self._is_explicit_cors_origin(origin):
            return True

        host = request.headers.get("host", "")
        if not host:
            return False

        expected_scheme = "https" if self.tls_enabled else "http"
        parsed = urlsplit(origin)
        expected_origin = f"{expected_scheme}://{host}"
        return (
            parsed.scheme == expected_scheme
            and parsed.netloc == host
            and parsed.path in ("", "/")
            and expected_origin == origin.rstrip("/")
        )

    def _is_websocket_upgrade_attempt(self, request: HTTPRequest) -> bool:
        """Return True when the request appears to target the WebSocket handshake path."""
        if (
            request.method != "GET"
            or request.raw_target != "/notes/ws"
            or not websocket_route_enabled(request.raw_path)
        ):
            return False
        return any(
            (
                request.headers.get("upgrade"),
                request.headers.get("connection"),
                request.headers.get("sec-websocket-key"),
                request.headers.get("sec-websocket-version"),
                request.headers.get("origin"),
            )
        )

    def _process_request(
        self,
        data: bytes,
        client_socket: Any,
        client_address: tuple[str, int],
        request_num: int,
    ) -> bool:
        """Delegate request orchestration to the extracted request pipeline."""
        return self._request_pipeline.process(
            data,
            client_socket,
            client_address,
            request_num,
        )

    def _receive_request(
        self,
        client_socket: Any,
        idle_timeout: float | None = None,
    ) -> bytes:
        """Delegate to :func:`xferry.http.io.receive_request`."""
        received = self._receive_request_result(client_socket, idle_timeout=idle_timeout)
        try:
            return received.data
        finally:
            received.release_body_reservation()

    def _receive_request_result(
        self,
        client_socket: Any,
        idle_timeout: float | None = None,
    ) -> RequestReceiveResult:
        """Receive a request and retain any body-memory reservation."""
        return _receive_request_result_io(
            client_socket,
            max_upload_size=self.max_upload_size,
            max_header_size=self.max_header_size,
            idle_timeout=idle_timeout,
            body_idle_timeout=self.body_idle_timeout,
            body_timeout=self.body_timeout,
            body_min_rate_bytes_per_second=self.body_min_rate,
            on_reject=self._record_receive_rejection,
            body_memory_budget=self._body_memory_budget,
        )

    def _handle_notepad_ws(
        self,
        sock: Any,
        request: HTTPRequest,
    ) -> None:
        """Compatibility delegate to the WebSocket runtime frame loop."""
        self._websocket_runtime.set_handle_message(self._handle_ws_message)
        self._websocket_runtime.handle_session(sock, request)

    def _upgrade_websocket(self, sock: Any, request: HTTPRequest) -> bool:
        """Delegate admission and session cleanup to the WebSocket runtime."""
        self._websocket_runtime.set_handle_message(self._handle_ws_message)
        return self._websocket_runtime.upgrade(sock, request)
