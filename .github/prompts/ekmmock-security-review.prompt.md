---
description: 'Review EkmMock trust boundaries and secret handling without modifying code.'
agent: 'EkmMock Security'
---

Read [repository rules](../copilot-instructions.md), the
[spec](../../spec/ekm-proxy-mockhsm-spec.md) and the imported
[security-review skill](../skills/security-review/SKILL.md).

Review ${input:scope:the current implementation}. Prioritize spec sections 4-6
and 8: client CN/root trust by namespace, TLS policy, port separation, console
authorization/antiforgery, encrypted key storage, crypto-shred, integrity checks,
DEK masking/reveal/audit and safe errors/logging.

Return evidence-backed findings with file locations, spec references, severity,
confidence and focused fixes. Treat required RSA-OAEP SHA-1 interoperability and
documented simulator limitations accurately. Do not edit code, print secret values,
run destructive tests or create a report file unless requested.
