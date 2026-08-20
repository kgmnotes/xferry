# ADR-001: Handler registry

- **Status:** accepted

## Context

HTTP dispatch, CORS, browser mutation checks, discovery, and the UI must agree
on method names and policy. Inferring handlers from a mixin hierarchy makes
that agreement implicit and difficult to validate.

## Decision

Store every built-in method in `CoreMethodSpec`, including its handler name,
mutation flag, CORS policy, UI group, and exposure note. Build the runtime
`HandlerRegistry` and other policy projections from those specifications.

Plugins register explicitly after core handlers. They cannot replace a core
method unless the operator enables core override.

## Consequences

- One typed registry owns built-in method policy.
- `PING.supported_methods`, CORS, browser guards, and UI grouping can be tested
  against the same source.
- Adding a method requires a specification, handler, tests, and API
  documentation.
