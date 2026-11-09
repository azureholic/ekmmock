# EkmMock Copilot customizations

Selected from [github/awesome-copilot](https://aka.ms/awesome-copilot) after reading
[the EkmMock specification](../../spec/ekm-proxy-mockhsm-spec.md).
Pinned upstream revision: `b13e55f85ffdf451d40d09839cb1e337bf3eda98`.
The imported content is MIT licensed; see [LICENSE](LICENSE).
[manifest.json](manifest.json) records each upstream file, SHA-256 hashes and local adaptations.

These are workspace-local customizations, not application code or globally installed
plugins. No extensions, MCP servers, runtime packages or Azure resources were installed.

## Entry points

VS Code loads [repository instructions](../copilot-instructions.md) automatically.
File-specific instructions live in [instructions](../instructions), custom agents in
[agents](../agents), skills in [skills](../skills), and prompt files in
[prompts](../prompts). Skill bundles include all upstream reference files.

Use the prompt picker or these slash commands:

| Prompt | Purpose |
| --- | --- |
| `/ekmmock-plan` | Plan M1-M9 with acceptance-test mappings; no implementation |
| `/ekmmock-implement-milestone` | Implement one milestone and its build/test/commit gates |
| `/ekmmock-test` | Unit, protocol, real-Kestrel TLS, inspector and UI acceptance tests |
| `/ekmmock-security-review` | Read-only trust-boundary and secret-handling review |
| `/ekmmock-record-decision` | Record an evidence-backed choice in `docs/DECISIONS.md` |
| `/ekmmock-packaging` | M9 container, VM/ACI Bicep and CI preparation; no deployment |

Agent picker names: **EkmMock .NET**, **EkmMock Plan**, **EkmMock Security** and
**EkmMock Bicep**. Security has read/search tools only. Other agents inherit host
tools and the user's model rather than pinning obsolete upstream model/tool names.
Optional tools referenced in upstream guidance must be available before use.

## Selection

| Resources | Spec coverage |
| --- | --- |
| .NET engineer agent; C# instructions | .NET 10, Minimal APIs, CLI, project boundaries (M1-M8) |
| Planning agent; implementation-plan skill | Milestone dependencies and testable completion gates |
| xUnit and C# async skills | RFC vectors, failure cases, deadline and capture behavior |
| Blazor instructions; Fluent UI skill and references | Interactive Server console and live inspector (M5-M6) |
| Security agent; security-review skill and references | mTLS, namespaces, key protection, reveal/audit/export boundaries |
| Bicep agent/instructions; multi-stage Dockerfile skill | Linux/OpenSSL containers and VM/ACI TCP pass-through (M9) |
| GitHub Actions hardening skill and references | CI token permissions, action pinning and secret protection |
| Decision-record skill | Required UI/exporter/crypto API/concurrency decision evidence |

The upstream revision has no `prompts` directory. Its reusable prompt workflows
are distributed as skills. The six local `.prompt.md` files are EkmMock-specific
launchers derived from the imported agents/skills, not unmodified upstream prompts.

## Compatibility adaptations

The spec governs all resources. Imported defaults have been narrowed to avoid:

- EF Core/databases, AI integrations, extra state/validation/chart packages,
  telemetry, generic ProblemDetails and JWT on the EKM port.
- NUnit/MSTest/FluentAssertions defaults instead of xUnit + Shouldly.
- Indiscriminate async exception wrapping or cancellation of synchronous crypto.
- Alpine/distroless substitutions for the required Linux/OpenSSL runtime.
- Alternative Azure hosting or TLS-terminating ingress in front of EKM.
- Extra ADR directories, unsolicited plan/report files, fixed model selections
  and unavailable tool identifiers.

Fluent UI is the selected console library; see [DECISIONS.md](../../docs/DECISIONS.md).
The generic security references supplement, but do not replace, C#/.NET-specific review
and the spec's explicit RSA-OAEP SHA-1 interoperability requirement.
General REST, production/cloud architecture, modernization, alternative test-framework
and unrelated language resources were deliberately excluded.

## Updating

Review upstream changes before replacing any file. The manifest distinguishes
unmodified reference files, adapted upstream resources and local launchers.
Preserve local spec constraints and the MIT notice; recheck front matter, relative
links, bundled references and hashes after an update.
