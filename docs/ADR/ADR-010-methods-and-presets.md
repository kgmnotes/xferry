# ADR-010: Always-on methods and launch presets

- **Status:** accepted

## Context

Method availability becomes misleading if launch modes, the UI, CORS, and the
handler registry expose different capability sets. Operators still need
convenient defaults for loopback, protected local, and direct public use.

## Decision

Keep one always-on built-in method surface: `GET`, `HEAD`, `POST`, `PUT`,
`PATCH`, `DELETE`, `OPTIONS`, `FETCH`, `INFO`, `PING`, `NONE`, `NOTE`, and
`SMUGGLE`. An authorized matching Advanced Session may also route a
syntactically valid unregistered method to an upload.

`PING.supported_methods` reports availability. `method_groups` is presentation
metadata only.

The `local`, `local-secure`, and `public-direct` presets select configuration
defaults and validation posture. They do not hide, add, or remove methods.
Explicit INI, environment, and CLI values remain authoritative over preset
defaults.

## Consequences

- Every deployment must account for the full sensitive method surface.
- A preset name is not an authorization boundary.
- Method changes must update the registry, handlers, CORS and browser policy,
  discovery, UI, tests, and API documentation together.
