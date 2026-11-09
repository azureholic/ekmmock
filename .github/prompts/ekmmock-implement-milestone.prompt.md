---
description: 'Implement one EkmMock milestone with its required tests and completion gates.'
agent: 'EkmMock .NET'
---

Read [repository rules](../copilot-instructions.md) and the complete
[spec](../../spec/ekm-proxy-mockhsm-spec.md).

Implement ${input:milestone:the next incomplete milestone in section 13}.
First verify prerequisite milestones and Git availability. Do not skip ahead.
Use the imported [xUnit](../skills/csharp-xunit/SKILL.md) and
[async](../skills/csharp-async/SKILL.md) skills where applicable. Use the
[Fluent UI skill](../skills/fluentui-blazor/SKILL.md) for console work; Fluent UI
is the selected component library.

Add focused tests proving the milestone's MUSTs and acceptance criteria. Build with
warnings as errors and run the relevant tests; measure required thresholds rather
than claiming them from inspection. Commit the validated milestone before proceeding
to another, but do not initialize Git or change Git configuration without permission.
Report blockers and unresolved spec conflicts explicitly. Never expose key material
in diagnostics or reports.
