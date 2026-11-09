---
description: 'Guidelines for building C# applications'
applyTo: '**/*.cs'
---

# C# Development

## EkmMock scope (local adaptation)

Follow [repository rules](../copilot-instructions.md) and the
[spec](../../spec/ekm-proxy-mockhsm-spec.md). Use .NET 10 and the section 16 layout.
The EKM contract is not a generic REST API. Do not add databases, validation packages,
alternate authentication schemes, telemetry exporters or API documentation packages
unless the spec calls for them. Use xUnit + Shouldly and central package management.

## C# Instructions
- Always use the latest version C#, currently C# 14 features.
- Comment only non-obvious intent; avoid narrating each function.

## General Instructions
- Make only high confidence suggestions when reviewing code changes.
- Write code with good maintainability practices, including comments on why certain design decisions were made.
- Handle edge cases and write clear exception handling.
- Record non-obvious dependency choices in `docs/DECISIONS.md`.

## Naming Conventions

- Follow PascalCase for component names, method names, and public members.
- Use camelCase for private fields and local variables.
- Prefix interface names with "I" (e.g., IUserService).

## Formatting

- Apply code-formatting style defined in `.editorconfig`.
- Prefer file-scoped namespace declarations and single-line using directives.
- Insert a newline before the opening curly brace of any code block (e.g., after `if`, `for`, `while`, `foreach`, `using`, `try`, etc.).
- Ensure that the final return statement of a method is on its own line.
- Use pattern matching and switch expressions wherever possible.
- Use `nameof` instead of string literals when referring to member names.
- Document public contracts when their behavior or security constraints need clarification.

## Project Setup and Structure

- Guide users through creating a new .NET project with the appropriate templates.
- Explain the purpose of each generated file and folder to build understanding of the project structure.
- Demonstrate how to organize code using feature folders or domain-driven design principles.
- Show proper separation of concerns with models, services, and data access layers.
- Explain the Program.cs and configuration system in ASP.NET Core 10 including environment-specific settings.

## Nullable Reference Types

- Declare variables non-nullable, and check for `null` at entry points.
- Always use `is null` or `is not null` instead of `== null` or `!= null`.
- Trust the C# null annotations and don't add null checks when the type system says a value cannot be null.

## Authentication and Authorization

- Use namespace-specific mTLS CN/root trust on the EKM port.
- Use LoopbackOnly or Microsoft.Identity.Web OIDC on the separate console port.
- Enforce local-port separation and console authorization exactly as specified.

## Validation and Error Handling

- Prefer built-in validation and explicit guards; avoid extra validation dependencies.
- Explain the validation pipeline and how to customize validation responses.
- Demonstrate a global exception handling strategy using middleware.
- Show how to create consistent error responses across the API.
- Use the specified ProxyError body, statuses and safe messages for EKM errors.

## API Versioning and Documentation

- Require the exact `api-version` query parameter and document the EKM wire contract.
- Do not introduce API-versioning or Swagger packages just for generic conventions.

## Logging and Monitoring

- Use built-in ILogger with the JSON console formatter.
- Explain the logging levels and when to use each.
- Preserve request and correlation IDs without logging bodies, headers or key values.
- Explain how to monitor API performance, errors, and usage patterns.

## Testing

- Always include test cases for critical paths of the application.
- Guide users through creating unit tests.
- Do not emit "Act", "Arrange" or "Assert" comments.
- Copy existing style in nearby files for test method names and capitalization.
- Explain integration testing approaches for API endpoints.
- Demonstrate how to mock dependencies for effective testing.
- Show how to test authentication and authorization logic.
- Explain test-driven development principles as applied to API development.

## Performance Optimization

- Keep loaded keys in memory and file I/O off the hot path; do not cache crypto responses.
- Explain asynchronous programming patterns and why they matter for API performance.
- Keep inspector buffering bounded and its producer non-blocking.
- Explain how to measure and benchmark API performance.

## Deployment and DevOps

- Use the section 11 multi-stage Dockerfile with the specified .NET 10 Linux images.
- Explain CI/CD pipelines for NET applications.
- Target the specified Linux VM and ACI deployment options with TLS terminating in Kestrel.
- Show how to implement health checks and readiness probes.
- Explain environment-specific configurations for different deployment stages.
