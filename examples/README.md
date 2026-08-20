# Examples

These examples exercise the current source checkout. Start with the root
[README](../README.md#install-from-source); no released package or container
image is available.

| Path | Scenario |
| --- | --- |
| [`basic_file_server.sh`](basic_file_server.sh) | Local HTTPS file share with random Basic Auth and uploads-only access |
| [`advanced_upload_nginx.md`](advanced_upload_nginx.md) | Token-scoped Advanced upload with a custom method behind nginx |
| [`notepad_client.py`](notepad_client.py) | Secure Notepad ECDH client flow |
| [`docker/`](docker/) | Local multi-stage Docker build with named volumes |

The Compose example builds `xferry:local` from the checkout. Running
`docker compose -f examples/docker/docker-compose.yml down` preserves its
named volumes. Adding `--volumes` also deletes uploads, notes, and ACME state.
