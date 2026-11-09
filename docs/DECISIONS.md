# Implementation decisions

## Console component library

- **Decision:** Use Microsoft Fluent UI Blazor
  (`Microsoft.FluentUI.AspNetCore.Components`) for the Blazor Interactive Server
  console and its UI components.
- **Reason:** The user selected Fluent UI from the two options permitted by
  [spec section 3](../spec/ekm-proxy-mockhsm-spec.md).
- **Alternative:** The default Bootstrap template was permitted but not selected.
- **Implementation:** Add a compatible version through central package management
  when the console milestone is implemented. Use the Fluent UI skill and preserve
  the spec's accessibility, security, live-update and small SVG chart requirements.
  Add optional companion packages only when needed.
- **Status:** Chosen; the console has not yet been implemented or verified.
