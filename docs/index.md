# xferry

`xferry` is a controlled HTTP toolkit for Secure Web Gateway testing. It
combines file transfer, custom HTTP methods, a Secure Notepad, and transport
experiments in one local web UI and HTTP API.

!!! warning "Authorized testing only"
    Use systems and data you own or are authorized to test. An external
    deployment needs the full controls in the [security policy](security.md).

## Start here

- [Choose portable, managed Linux, or container installation](quick-start.md)
- [Check the managed Linux support matrix](managed-hosts.md)
- [Choose a test workflow](scenarios.md)
- [Use a disposable SSH tunnel](disposable-ssh-tunnel.md)
- [Manage data and process lifecycle](operations.md)
- [Configure a public-direct deployment](public-direct.md)
- [Integrate with the HTTP and WebSocket API](api.md)
- [Look up generated CLI help](cli-reference.md)

Portable installs are owned by pipx, managed Linux installs by the signed SCIE
lifecycle, and containers by immutable GHCR version tags or digests. Contributor
source builds remain documented separately and are not the first user path.

Developer reference material includes the [architecture](architecture.md),
[frontend contract](frontend-contract.md), and [active ADR set](ADR/README.md).
