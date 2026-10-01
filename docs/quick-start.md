# Quick start

Choose one lifecycle owner. Use pipx for a portable CLI, the signed installer
for a managed Linux service, or an immutable GHCR image for a container. Do not
mix their upgrade or uninstall commands.

## Portable

Python 3.10 through 3.14 is supported. If pipx is already available, first
success is two commands:

```console
pipx install xferry
xferry run --preset local --open
```

On Windows, bootstrap pipx once from PowerShell:

```powershell
py -m pip install --user pipx
py -m pipx ensurepath
```

On Linux, install pipx with your distribution's package manager. For
Ubuntu/Debian:

```console
sudo apt update
sudo apt install pipx
pipx ensurepath
```

On macOS, install pipx with [Homebrew](https://brew.sh):

```console
brew install pipx
pipx ensurepath
```

Open a new terminal after `ensurepath`, then run the two first-success commands.
The server listens on <http://127.0.0.1:8080>.

## Managed Linux

Managed setup requires root, systemd, and one of the exact combinations in the
[generated support matrix](managed-hosts.md). Select the installer for the host
architecture from GitHub Release `v0.2.0`, download it and its detached
signature, and follow the [privileged verification order](security.md#privileged-installer-verification-order).
Never stream an installer into a shell.

After verification, install and configure a private service:

```console
sudo sh ./install-linux-x86_64.sh
sudo xferry setup --private
sudo xferry status
sudo xferry doctor --deep
```

Use `install-linux-aarch64.sh` on arm64. Setup prints credentials once; store
them in a secret manager. See [Operations](operations.md#managed-linux-lifecycle)
for logs, exact-version update, rollback, and uninstall.

## Container

The released image supports `linux/amd64` and `linux/arm64`. Run the immutable
v0.2.0 image on loopback with a named data volume:

```console
docker run --rm --name xferry \
  --publish 127.0.0.1:8080:8080 \
  --volume xferry-data:/data \
  ghcr.io/kgmnotes/xferry:v0.2.0
```

For repeatable deployments, replace the version tag with the digest recorded
for that release. See [Operations](operations.md#container-lifecycle) and the
[public deployment guide](public-direct.md) before exposing a container.

## Send a first file

In the UI:

1. Open **Upload**.
2. Select a small authorized test file.
3. Send it and confirm the inline HTTP status, saved server path, and size.
4. Open **Files**, download the file, and delete it.

The same flow works with curl:

```console
printf 'authorized test\n' > sample.txt
curl --fail-with-body \
  --request POST \
  --header 'X-File-Name: sample.txt' \
  --data-binary @sample.txt \
  http://127.0.0.1:8080/uploads

curl --fail-with-body --request INFO http://127.0.0.1:8080/uploads/
curl --fail-with-body http://127.0.0.1:8080/uploads/sample.txt
```

## Try a custom method

The **Requests** panel lists the methods returned by `PING`. The built-in
surface includes standard methods plus `FETCH`, `INFO`, `PING`, `NONE`, `NOTE`,
and `SMUGGLE`. Arbitrary unregistered methods require an authorized Advanced
Session; see the [API journey](api.md#advanced-sessions-upload).

## Stop and protect data

Press `Ctrl+C` for a portable process, use `sudo xferry stop` for a managed
service, or stop the container. Reusing the same portable directory, managed
data root, or container volume preserves uploads and encrypted note state.

Do not bind publicly as a shortcut. Use `xferry run --preset local-secure` for
trusted-local protection, and follow [Public deployment](public-direct.md) for
external service controls.
