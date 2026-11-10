# EkmMock implementation todo list

Status of the work items tracked while implementing [the spec](./ekm-proxy-mockhsm-spec.md), as of 2026-11-10.
Milestones follow section 13 of the spec; each was built, tested and committed before the next one started.

| Status | Meaning |
| --- | --- |
| done | Implemented, tests run, committed and pushed |
| not done | Deliberately not performed (see notes) |

## Milestones

| ID | Item | Depends on | Status | Commit | Scope |
| --- | --- | --- | --- | --- | --- |
| m1-crypto | M1: crypto engine | none | done | `2f7d295` | `EkmMock.Crypto`: AES-KW/KWP, RSA-OAEP, key generation, encrypted key store, namespaces, self-test |
| m2-ekm-api | M2: EKM API | m1-crypto | done | `47f75b3` | Routing, request/response types, ProxyError, base64url, handlers over `ICryptoBackend` |
| m3-mtls | M3: EKM endpoint mTLS | m2-ekm-api | done | `adeaec1` | TLS 1.3, cipher policy, custom root trust, per-namespace auth, certificate hot reload, connection capture |
| m4-inspector | M4: traffic inspector | m3-mtls | done | `ee34dac` | Capture pipeline, ring buffer, JSONL, masking, overhead benchmark |
| m5-console | M5: console shell | m4-inspector | done | `f81ccfb` | Fluent UI Blazor console, auth modes, port separation, Live traffic, detail, Connections, Dashboard |
| m6-console-mgmt | M6: console management | m5-console | done | `0efdd5f` | Keys, namespaces and trust, certificates, playground, audit log, about |
| m7-limits-faults | M7: limits, faults, metrics | m6-console-mgmt | done | `0a27ad8` | Limits, fault injection, Prometheus metrics, structured log levels |
| m8-cli | M8: `ekmmock` CLI | m7-limits-faults | done | `510460d` | init, certs, key and trust commands, conformance suite, bench |
| m9-packaging | M9: packaging and docs | m8-cli | done | `c08616d` .. `a066623` | Dockerfile, compose, CI, Bicep (VM and ACI), `e2e.sh`, README, RUNBOOK, RESULTS template |

## Follow-up items

| ID | Item | Depends on | Status | Commit | Notes |
| --- | --- | --- | --- | --- | --- |
| final-security-review | Final security review and fixes | m9-packaging | done | `db6d3fc`, `022fb88` | No critical or high findings. Both medium findings fixed (fail-closed identity check, byte-bounded inspector memory). Low findings fixed or documented; see "Security review follow-up" in `docs/DECISIONS.md` |
| cleanup-cng-keys | Clean leaked Windows CNG key files | final-security-review | not done | none | Test runs left key container files in `%APPDATA%\Microsoft\Crypto\Keys`. Not deleted because the folder also holds the user's own keys. See open question 46 in `docs/OPEN-QUESTIONS.md` |

## Not verified

Items that could not be checked offline are listed in `docs/RESULTS.md` and `docs/OPEN-QUESTIONS.md`:

- Real Azure Managed HSM end-to-end (`deploy/azure/e2e.sh`).
- The Bicep templates and the VM boot flow (`az deployment group validate` and `what-if` were not run).
- ACI non-root binding of port 443.
- Entra sign-in against a real tenant.
- The root cause of the intermittent Windows client-certificate finding (open question 77).
