<!--
Thank you for your contribution!
Please fill out the sections below; delete any that do not apply.
-->

## Summary

<!-- What does this PR do? Why is it needed? -->

## Type of change

- [ ] Bug fix (non-breaking)
- [ ] New feature (non-breaking)
- [ ] Breaking change
- [ ] Security fix
- [ ] Documentation
- [ ] Refactor / chore

## Checklist

- [ ] Tests added/updated and `pytest` passes locally
- [ ] Tooling installed with `PIP_CONSTRAINT=constraints/ci.txt pip install -e ".[dev,lint,test]"`
- [ ] `pre-commit run --all-files` passes
- [ ] `ruff check xferry tests tools` passes
- [ ] `ruff format --check xferry tests tools` passes
- [ ] `mypy xferry` passes with no new errors
- [ ] `CHANGELOG.md` updated under `[Unreleased]`
- [ ] Relevant documentation updated (README / API.md / docs/ADR)

## Security impact

<!-- If this change touches auth, TLS, crypto, path handling, or OPSEC, describe the threat model impact here. Otherwise write "none". -->

## How to test

<!-- Commands, endpoints, or manual steps a reviewer can use to validate. -->
