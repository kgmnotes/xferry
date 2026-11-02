# ADR-013: Unified deployment lifecycle and bounded request capacity

- **Status:** accepted (2026-11-02). Supersedes the connection-worker design in ADR-005 and the legacy migration behavior in ADR-011.

A real 1-vCPU/889-MiB VPS audit found that native setup failed for an existing root-owned shared folder, idle browser connections consumed processing capacity, and backend-specific installation rules leaked into menus and public ports.

The product has three journeys: foreground `run --config`, native systemd setup, and Docker Compose setup. A shared management application owns instance resolution, plans and operation results. Backend adapters perform mutations under locks. Schema2 deployment manifests record identity, artifact, host profile and resource ownership; status is observed from files and the process supervisor. The instance registry is a discovery index. Observed states are absent, incomplete, stopped, running, retained and broken.

A version1 modern INI profile declares host-facing paths and ports. Backends compile isolated runtime settings: native binds the external share into its sandbox, Compose maps it to `/data/files` and maps host443 to internal8443. TLS state, notes and transfer journals belong to one explicit private state root. Unsupported old formats are refused without conversion or mutation.

The native adapter grants minimal directory ACLs without recursive ownership changes and records the previous/granted ACL and inode identity. Purge restores only unchanged owned resources and reports retained edits. Uninstall retains config/auth/private state. Purge removes owned deployment resources, manifest and discovery index; it always preserves the external share. A separately installed controller is removed using its package manager.

The server keeps its synchronous implementation with bounded connection owner threads. Separate finite gates admit TCP32, TLS2, short operations4, bulk transfers4 and WebSockets8. Password verification admits16 total operations with2 active checks. Authentication precedes body allocation and transfer admission. Idle keep-alive and WebSocket sockets reserve no processing worker. Bulk and short-operation classification follows routes. Socket shutdown cancels blocked I/O and gate waiters release leases exactly once.

Body admission defaults to one eighth of effective RAM, including cgroup limits, bounded to32–128MiB. This is an aggregate request-body budget, not an RSS limit. Operators can tune every independent gate. The initial implementation keeps PBKDF2 and introduces no positive authentication cache or session protocol.

The Upload view starts with the file chooser, Send and queue. Protocol configuration and inspectors use collapsed advanced sections. Existing custom HTTP methods, encrypted transfers and Notepad remain product capabilities.

Acceptance includes installed artifacts, constrained resources, real browser TLS/Basic traffic, concurrent transfers/WS, lifecycle/reboot/controlled certificate renewal, and final removal preserving share hashes. Public release publication is a separate action.
