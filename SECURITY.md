# Security Policy

`@rezprotocol/core` is the cryptographic and protocol foundation of the Rez ecosystem. Security issues here may have wide impact across all downstream packages — we take them seriously.

## Reporting a Vulnerability

**Please do not open public issues for suspected vulnerabilities.**

Use [GitHub Security Advisories](https://github.com/rezprotocol/rez-core/security/advisories/new) to report privately. Only the reporter and the repository maintainers can view the report.

## What to expect

- **Acknowledgement** within 72 hours.
- **Initial assessment** (severity, scope, reproduction) within 7 days.
- **Fix + coordinated disclosure** within 90 days of report — sooner for high-severity issues.
- **Credit** in the security advisory and release notes if you'd like (let us know).

## Scope

In scope:
- Cryptographic flaws in the protocol or its implementation (X3DH, Double Ratchet, signing, AEAD)
- Capability-model bypasses, identity spoofing, message forgery, replay attacks
- Authentication / authorization weaknesses in the wire protocol

Out of scope:
- Social engineering of users or operators
- Attacks requiring active access to the user's device or keystore
- Issues affecting only un-tagged `main`-branch code

## Threat model and posture

- **Threat model** — [`docs/security.md`](./docs/security.md): what the protocol protects against, cryptographic guarantees, explicit limitations
- **Audit history + disclosure posture** — [`docs/SECURITY_POSTURE.md`](./docs/SECURITY_POSTURE.md)
