---
description: 'Add or run spec-driven EkmMock unit, TLS, inspector and console acceptance tests.'
agent: 'EkmMock .NET'
---

Read [repository rules](../copilot-instructions.md), the
[spec](../../spec/ekm-proxy-mockhsm-spec.md) and the imported
[xUnit skill](../skills/csharp-xunit/SKILL.md).

Test ${input:scope:the current milestone}. Trace each selected requirement to an
executable test. Use xUnit + Shouldly; RFC vectors for AES-KW/KWP;
WebApplicationFactory for M2 protocol tests; real Kestrel/generated certificates
for mTLS; and bUnit or C# Playwright for UI behavior.

Include negative cases, cross-namespace/port isolation and masked persistence/export
checks when applicable. Assert the exact timing thresholds required by the spec.
Use only synthetic test keys and avoid secret-bearing assertion output.
Run the smallest relevant test set and report actual pass/fail, measured results
and tests not run. Do not start a later milestone or deploy Azure resources.
