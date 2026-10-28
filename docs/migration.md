# Migrate an existing configuration

Version `0.3.1` simplifies the CLI and settings. Versions `0.2.x` use the
previous interface; the [v0.2.0 instructions](archive/0.2.0-installation.md)
remain archived. Upgrade the runtime and configuration together using the
matching [versioned release](https://github.com/kgmnotes/xferry/releases/tag/v0.3.1).
Back up configuration, protected credentials, files and private state.

## Native Linux service from the old release

Use the **new portable CLI** to update an existing `0.2.x` native service. The
installed old CLI cannot perform the configuration conversion itself. The exact
version keeps the controller consistent through update and rollback:

```bash
pipx run --spec xferry==0.3.1 xferry update \
  --to 0.3.1 --config /etc/xferry/xferry.ini --dry-run
pipx run --spec xferry==0.3.1 xferry update \
  --to 0.3.1 --config /etc/xferry/xferry.ini
```

The update verifies the signed release, stages the converted configuration and
new systemd unit, activates the runtime and checks authenticated health. A failed
activation restores the previous runtime, configuration, unit and credentials.
Files, notes and ACME state keep their existing locations. A stopped service
returns to its stopped state after the health check.

The updater keeps a protected deployment checkpoint associated with the
verified previous release. To return to the retained `0.2.1` release, use the
same new controller:

```bash
pipx run --spec xferry==0.3.1 xferry rollback \
  --to 0.2.1 --config /etc/xferry/xferry.ini
```

Rollback restores the matching old configuration and unit without moving data
or generating a new password. The new controller can upgrade the service again;
settings saved for the newer release are retained. Do not manually convert the
active old native configuration with `config`: the editor blocks this because
its old unit would no longer be able to start. The update performs both changes
together.

A reinstall with retained data remains a recovery option when a direct update
cannot be prepared. Do not use `--purge-data` for that recovery; it deletes the
state needed for reuse.

## One-time conversion

Open the old profile in the interactive editor:

```console
xferry config --config /path/to/xferry.ini
```

For a native installation, use the update procedure above instead. For a
foreground profile, the editor offers conversion and validation before applying
the new profile. Restart the foreground server afterward with:

```console
xferry run --config /path/to/xferry.ini
```

Migration saves a protected backup named `.xferry.ini.before-migration` beside
`xferry.ini`. A protected `.xferry.ini.state.json` records the retained absolute
files/private-state paths. Keep it with the configuration. Existing file-backed
passwords, encrypted-transfer sidecars, notes and ACME state are preserved.
Inline passwords move to a protected auth file. Conversion does not move files.
Existing legacy encrypted journals require supported POSIX filesystem operations;
unsupported platforms, including Windows, refuse that conversion before writing.
See [Encrypted transfer migration](encrypted-transfers.md#migrating-existing-encrypted-state)
for the scope of this restriction.
If an old relative data root cannot be resolved reliably, supply the original
absolute path before conversion.

The runtime rejects old public names after conversion, including retired
`XFERRY_*` environment variables. Remove these from shell scripts, service
wrappers and Compose environment sections. Error messages do not echo retired
inline passwords. Mixed old/new mode settings and an old public preset with its
strict checks explicitly disabled require manual review; conversion does not
silently weaken public requirements.

## Command changes

| Previous interface | Current interface |
| --- | --- |
| `install`, then `setup` | `setup` completes installation and health verification |
| `configure` | `config` opens the editor |
| `examples` | Examples in command help and the quick start |
| `--target`, `--output` | `--config FILE`; `setup --docker` chooses a new Docker deployment |
| `config set … --apply` | `config set …` applies automatically; `--dry-run` previews |
| `run --check-config` | `config check` |
| `run --print-config` | `config show --all` |
| `run --write-sample-config` | `config` creates a saved profile |

## Setting changes

| Previous name | Current equivalent |
| --- | --- |
| `preset`, `public_direct` | `access = private`, `public`, or `lab` |
| `tls`, `letsencrypt`, `sslip` | `https_mode = off`, `auto`, `domain`, `files`, or `self-signed`; CLI `--https` |
| `quiet`, `debug` | `log_level = warning`, `info`, or `debug` |
| `json_log` | `log_format = json` or `text` |
| `root_dir`, `--dir` | `files_dir` selects the exact shared folder; private state is automatic |
| Inline `auth` / `--auth` / `XFERRY_AUTH` | Protected `auth_file`; generate/reset through the credentials action |
| `acme_staging` | `acme_server = staging` |
| Persistent `open_browser` | Launch-only `--open` |

The old data-root setting referred to a parent of `uploads/`; the new files-folder
setting refers to the folder itself. Migration retains the old `uploads/` path.
A fresh foreground profile uses a stable user data folder instead of the current
directory. Read [Settings](settings.md) for all current names and defaults.
