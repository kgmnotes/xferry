# Upgrade notes

This architecture deliberately replaces the previous CLI, configuration and
deployment formats. It accepts operator INI files with `[server] config_version =
1` and deployment manifests with schema 2. Unsupported state is rejected without
changing it. There is no automatic conversion, legacy unit activation or
cross-schema rollback in the new controller.

The managed deployment compatibility line starts at 0.5.0. Public release
acceptance selects and validates only predecessors at or above that minimum;
0.4.x is not an update/rollback baseline for a 0.5.x deployment. Version 0.5.0 has
no eligible public predecessor, so its two-public-version gate remains blocked.
Public Pages deployment requires a later distinct compatible release to complete
the full acceptance matrix.

For an existing installation:

1. Keep the matching old controller and runtime available for rollback. Back up
   the old configuration, protected authentication file, shared folder, notes,
   encrypted sidecars and certificate state together.
2. Stop the old service with its original controller. Keep its data intact.
3. Install the current controller and create a fresh deployment using
   `xferry setup --backend native` or `xferry setup --backend docker`. Select an
   explicit shared folder and review the plan.
4. Re-enter the needed settings using the current reference. Verify TLS, Basic
   Auth and a complete upload/download/delete cycle before switching clients.
5. To recover the old deployment, stop the new one and restore its matching old
   controller, runtime and backed-up state. The new controller does not manage
   that old installation.

For a foreground profile, create a new file with
`xferry config --config /path/to/new-xferry.ini`, then use
`xferry run --config /path/to/new-xferry.ini`. Do not copy old INI keys wholesale.
Encrypted private storage may have its own compatibility requirements; consult
[encrypted transfers](encrypted-transfers.md) before reusing private state.

| Previous interface | Current interface |
| --- | --- |
| `setup --docker` | `setup --backend docker` |
| Persistent operation `--config FILE` | `--instance ID` |
| `uninstall --purge-data` | `uninstall --purge` |
| Backend guessed from a path or filename | Backend recorded in the versioned manifest |
| Old runtime INI inside a Docker deployment | Host-facing operator INI plus generated runtime mapping |
| Implicit conversion of old profiles | Explicit fresh setup and data review |

`--config FILE` selects a foreground profile for `run`, `config` or credentials.
It never selects a container or service. CLI aliases for the previous modes are
removed. [Historical v0.2.0 instructions](archive/0.2.0-installation.md) describe
only that old version.
