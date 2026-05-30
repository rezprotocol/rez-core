# Contributing to @rezprotocol/core

Thanks for considering a contribution. `@rezprotocol/core` is the cryptographic and protocol foundation of the Rez ecosystem; changes here affect every downstream package. Please read this before opening a PR.

## Getting started

```bash
git clone https://github.com/rezprotocol/rez-core.git
cd rez-core
npm install
npm test
```

## Code style

This codebase is **vanilla JavaScript, ESM only**.

- ES2022+: async/await, classes, native `import` / `export`
- `#privateField` / `#privateMethod()` for private members; `_protectedMethod()` convention for protected
- **No optional chaining (`?.`)** — use explicit `if` / `===` checks. Silent fall-through on `null` has bitten this codebase repeatedly.
- **No empty `catch` blocks** — every caught exception must be either handled or re-thrown. Swallowed errors hide correctness bugs.
- No TypeScript, no Babel/SWC, no transpilation.
- Tests use Node's built-in `node:test` runner.

## Architecture

This package is cross-runtime: it must work in Node, browsers, and Electron without modification. Do **not** add Node-specific APIs (`fs`, `child_process`, etc.) or DOM-specific APIs to `rez-core`. Those belong in `@rezprotocol/node` and the application layer, respectively.

Layer responsibilities and invariants across all Rez packages are documented in [`docs/ARCHITECTURE_GUARANTEES.md`](./docs/ARCHITECTURE_GUARANTEES.md).

## Tests

```bash
npm test
```

All PRs must pass tests. Cryptographic changes additionally require:
- Test vectors checked against the specification in `docs/`
- Adversarial test cases (negative tests for tampering, replay, downgrade)

## Pull request process

1. Fork → branch → push.
2. Open a PR against `main`.
3. Describe the change concretely (what + why; the *what* should match the diff).
4. CI runs tests.
5. Maintainer review. Cryptographic changes get extra scrutiny.

## Licensing

By submitting a contribution, you agree that your contribution will be licensed under the Apache License 2.0, the license of this repository (per Section 5 of the Apache License).

## Security disclosures

Please do **not** open public issues for security vulnerabilities. See [SECURITY.md](./SECURITY.md) for the disclosure process.
