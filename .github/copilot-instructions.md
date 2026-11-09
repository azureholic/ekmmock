# EkmMock implementation rules

Read [the complete specification](../spec/ekm-proxy-mockhsm-spec.md) before implementation.
Its normative sections 4, 5, 6 and 8 govern the protocol, security, crypto engine and inspector.
Imported Awesome Copilot resources are supplementary guidance, not permission to change the spec.
If Microsoft Learn's EKM API reference conflicts with the spec, stop the affected work and
record the discrepancy in `docs/OPEN-QUESTIONS.md`; do not guess.

## Workflow

- Implement M1 through M9 in the order in section 13. Build, pass the milestone's tests
  and commit it before starting the next milestone. If Git has not been initialized
  or committing is blocked, report that prerequisite rather than claiming completion.
- Prove each MUST with a test. Map tests to sections 13 and 14; distinguish measured
  results from expected results. Do not mark unexecuted tests as passed.
- Do not create planning documents unless requested. Record implementation choices in
  `docs/DECISIONS.md` and unresolved protocol questions in `docs/OPEN-QUESTIONS.md`.
- Use .NET 10, current compatible C#, Minimal APIs, System.Text.Json source generation,
  Blazor Interactive Server, xUnit and Shouldly. Keep NuGet dependencies minimal and
  pinned centrally in `Directory.Packages.props`.
- Use Microsoft Fluent UI Blazor for the console, as recorded in
  [DECISIONS.md](../docs/DECISIONS.md). Apply the Fluent UI skill when implementing
  console components.
- Follow the section 16 layout. Keep `EkmMock.Crypto` independent of ASP.NET Core.
  Do not introduce EF Core, databases, CQRS/event sourcing, AI integrations, distributed
  services, external crypto libraries or a real-HSM backend.
- Use built-in `ILogger` JSON logging. Do not add application telemetry or unsolicited
  outbound integrations. Console authentication and the explicit test-client flows
  must follow the spec.

## Non-negotiable boundaries

- EKM uses TLS 1.3, the two specified cipher suites and namespace-specific client CN
  plus custom root trust. Never substitute JWT authentication, OS trust, leaf fingerprint
  pinning, IP allow-lists or blanket certificate-validation bypasses.
- Separate EKM and console traffic by local port. Preserve missing-client-certificate
  JSON 401 handling and capture failed TLS handshakes before HTTP.
- Use the exact POST-only routes, longest-prefix namespace matching, snake_case JSON,
  base64url rules and ProxyError bodies. Do not substitute REST conventions or
  ProblemDetails for the EKM wire contract.
- Only `System.Security.Cryptography` performs crypto. Implement AES-KW/KWP per the
  RFCs if the selected runtime has no suitable built-in API; verify RFC test vectors.
  Preserve required RSA-OAEP SHA-1 interoperability alongside RSA-OAEP-256.
- Never expose private/secret key material outside the crypto engine. Preserve the
  specified DEK API behavior, masking, reveal gates, audit logging, zeroing and
  always-masked persistence/exports. Never include secret bytes in test diagnostics.
- Keep synchronous crypto synchronous; cancellation does not interrupt a running crypto
  operation. Use bounded, non-blocking inspector capture and count dropped records.
- LoopbackOnly must reject public console binds. Non-loopback console access requires
  Entra ID authorization. Use antiforgery and audit every state-changing console action.
- Benchmark the actual thresholds: inspector overhead p99 < 1 ms; section 14 latency
  limits; live updates within 1 s. Do not replace these with average timings.
- Containers use the specified .NET 10 Linux/OpenSSL images, non-root execution and
  a read-only root filesystem except the data volume. EKM TLS terminates in Kestrel,
  never at an HTTP ingress proxy. Deployment targets are the specified VM and ACI,
  not App Service, AKS or Container Apps.

## Imported resources

See [the customization guide](awesome-copilot/README.md) for agents, prompt launchers,
skill selection, adaptations, source pinning and license information.
