---
description: 'Prepare M9 Docker packaging, Azure Bicep and CI without deploying resources.'
agent: 'EkmMock .NET'
---

Read [repository rules](../copilot-instructions.md) and the complete
[spec](../../spec/ekm-proxy-mockhsm-spec.md). Verify M1-M8 prerequisites before
implementing M9. Apply the imported
[multi-stage Dockerfile skill](../skills/multi-stage-dockerfile/SKILL.md),
[Bicep instructions](../instructions/bicep-code-best-practices.instructions.md)
and [Actions hardening skill](../skills/github-actions-hardening/SKILL.md).

Prepare the specified server-plus-CLI Linux image, compose setup, VM/ACI templates,
end-to-end script and CI checks. Preserve Kestrel mTLS, loopback/Entra console
security, non-root execution, writable-volume boundaries and secret-safe parameters.
Build/lint and run container conformance when the required tools are available.
Report missing tools and unverified checks explicitly. Do not provision resources,
push images, publish packages or run destructive Azure scenarios without permission.
