---
description: 'Blazor component and application patterns'
applyTo: '**/*.razor, **/*.razor.cs, **/*.razor.css'
---

## EkmMock scope (local adaptation)

Follow [repository rules](../copilot-instructions.md) and section 8 of the
[spec](../../spec/ekm-proxy-mockhsm-spec.md). Use Interactive Server, not WebAssembly.
Keep secrets server-side; never persist reveal data in browser storage or exports.
Use Microsoft Fluent UI Blazor for console components, as recorded in
[DECISIONS.md](../../docs/DECISIONS.md), with built-in form validation and bounded
live updates. Follow the [Fluent UI skill](../skills/fluentui-blazor/SKILL.md).
Do not introduce a chart library, external telemetry or additional state-management packages.

## Blazor Code Style and Structure

- Write idiomatic and efficient Blazor and C# code.
- Follow .NET and Blazor conventions.
- Use Razor Components appropriately for component-based UI development.
- Prefer inline functions for smaller components but separate complex logic into code-behind or service classes.
- Async/await should be used where applicable to ensure non-blocking UI operations.

## Naming Conventions

- Follow PascalCase for component names, method names, and public members.
- Use camelCase for private fields and local variables.
- Prefix interface names with "I" (e.g., IUserService).

## Blazor and .NET Specific Guidelines

- Utilize Blazor's built-in features for component lifecycle (e.g., OnInitializedAsync, OnParametersSetAsync).
- Use data binding effectively with @bind.
- Leverage Dependency Injection for services in Blazor.
- Structure Blazor components and services following Separation of Concerns.
- Always use the latest version C#, currently C# 14 features like record types, pattern matching, and global usings.

## Error Handling and Validation

- Implement proper error handling for Blazor pages and API calls.
- Use logging for error tracking in the backend and consider capturing UI-level errors in Blazor with tools like ErrorBoundary.
- Implement validation using built-in DataAnnotations or explicit validation.

## Blazor API and Performance Optimization

- Utilize Blazor server-side or WebAssembly optimally based on the project requirements.
- Use asynchronous methods (async/await) for API calls or UI actions that could block the main thread.
- Optimize Razor components by reducing unnecessary renders and using StateHasChanged() efficiently.
- Minimize the component render tree by avoiding re-renders unless necessary, using ShouldRender() where appropriate.
- Use EventCallbacks for handling user interactions efficiently, passing only minimal data when triggering events.

## Caching Strategies

- Implement in-memory caching for frequently used data, especially for Blazor Server apps. Use IMemoryCache for lightweight caching solutions.
- Do not place secret values in localStorage or sessionStorage, or add distributed caches.
- Cache API calls by storing responses to avoid redundant calls when data is unlikely to change, thus improving the user experience.

## State Management Libraries

- Use Blazor's built-in Cascading Parameters and EventCallbacks for basic state sharing across components.
- Keep state management within the existing services and bounded inspector pipeline.
- For server-side Blazor, use Scoped Services and the StateContainer pattern to manage state within user sessions while minimizing re-renders.

## API Design and Integration

- Use HttpClient or other appropriate services to communicate with external APIs or your own backend.
- Implement error handling for API calls using try-catch and provide proper user feedback in the UI.

## Testing and Debugging

- All unit testing and integration testing should run cross-IDE (Visual Studio, VS Code, JetBrains Rider) so contributors aren't gated on a paid SKU.
- Test Blazor components and services with xUnit + Shouldly, using bUnit or Playwright
  for the spec's UI acceptance tests. Add mocking packages only if genuinely needed.
- Debug Blazor UI issues using browser developer tools, and use your IDE's debugger for backend and server-side issues.
- For performance profiling and optimization, use your IDE's diagnostics tools or `dotnet-trace` / `dotnet-counters` for cross-platform profiling.

## Security and Authentication

- Use the spec's LoopbackOnly or Microsoft.Identity.Web OIDC console authentication.
- Preserve antiforgery, allowed-user/group authorization and audit every state change.
- Use HTTPS for all web communication and ensure proper CORS policies are implemented.

## API Documentation and Swagger

- Document console APIs and the EKM protocol without adding Swagger dependencies by default.
