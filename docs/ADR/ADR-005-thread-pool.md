# ADR-005: Thread pool concurrency

- **Status:** accepted

## Context

The server uses blocking sockets, TLS, filesystem calls, and handler code.
Changing to an asynchronous runtime would require a broad rewrite without
removing the need to bound connections and storage work.

## Decision

Use one accept loop and a bounded `ThreadPoolExecutor`. Each accepted
connection runs on a worker. Keep-alive work remains on that worker, and an
active WebSocket occupies one worker until it closes.

Bound request bodies, timeouts, WebSocket admissions, and worker count
explicitly. The default worker count is 10; the default WebSocket admission
limit is half the worker count.

## Consequences

- The implementation matches its blocking libraries and is easy to inspect.
- Slow clients and WebSockets consume finite worker capacity.
- Operators must tune workers, memory admission, timeouts, and process limits
  as one capacity model.
