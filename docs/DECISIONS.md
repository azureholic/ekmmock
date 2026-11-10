# Implementation decisions

## Contents (by milestone)

The sections below, in the order they were written (an index only; the sections themselves are unchanged).

- [Console component library](#console-component-library)
- [M1: AES Key Wrap (A256KW / A256KWP)](#m1-aes-key-wrap-a256kw--a256kwp)
- [M1: Thread safety and instance pooling](#m1-thread-safety-and-instance-pooling)
- [M1: Test stack (xUnit version)](#m1-test-stack-xunit-version)
- [M1: Key store file format](#m1-key-store-file-format)
- [M1: Master key provider](#m1-master-key-provider)
- [M1: Engine error model, import gating and leak boundary](#m1-engine-error-model-import-gating-and-leak-boundary)
- [M1: Namespaces](#m1-namespaces)
- [M1: Build and repository conventions](#m1-build-and-repository-conventions)
- [M2: EKM request pipeline and host composition](#m2-ekm-request-pipeline-and-host-composition)
- [M2: EKM validation order (ordered-check table)](#m2-ekm-validation-order-ordered-check-table)
- [M2: EKM error mapping (one place)](#m2-ekm-error-mapping-one-place)
- [M2: Base64url (answer to open question 7)](#m2-base64url-answer-to-open-question-7)
- [M2: JSON and secret handling](#m2-json-and-secret-handling)
- [M2: Learn comparison](#m2-learn-comparison)
- [M2: Not covered / deliberately skipped](#m2-not-covered--deliberately-skipped)
- [M3: Where the code lives](#m3-where-the-code-lives)
- [M3: TLS stack (spec 5.1)](#m3-tls-stack-spec-51)
- [M3: Client certificate validation and authorization (spec 5.1)](#m3-client-certificate-validation-and-authorization-spec-51)
- [M3: Port separation (spec 5.4)](#m3-port-separation-spec-54)
- [M3: Connection capture (spec 7, 8.2, 14 test 21)](#m3-connection-capture-spec-7-82-14-test-21)
- [M3: Server certificate hot reload (spec 5.3)](#m3-server-certificate-hot-reload-spec-53)
- [M3: Learn comparison ("Configure networking and mTLS", read 9 November 2026)](#m3-learn-comparison-configure-networking-and-mtls-read-9-november-2026)
- [M3: Not covered / deliberately skipped](#m3-not-covered--deliberately-skipped)
- [M4: Where the code lives](#m4-where-the-code-lives)
- [M4: Capture pipeline (spec 8.1, 8.3)](#m4-capture-pipeline-spec-81-83)
- [M4: Secret handling in the inspector (spec 8.4)](#m4-secret-handling-in-the-inspector-spec-84)
- [M4: Reveal, retention and audit (spec 8.4, 5.4)](#m4-reveal-retention-and-audit-spec-84-54)
- [M4: Ring buffer, filters, feed (spec 8.3, 8.5)](#m4-ring-buffer-filters-feed-spec-83-85)
- [M4: JSONL files (spec 8.3)](#m4-jsonl-files-spec-83)
- [M4: Dashboard aggregates and contracts (spec 8.5)](#m4-dashboard-aggregates-and-contracts-spec-85)
- [M4: KQL snippet (spec 8.5)](#m4-kql-snippet-spec-85)
- [M4: Overhead benchmark (spec 8.3, 14 test 24)](#m4-overhead-benchmark-spec-83-14-test-24)
- [M4: Tests](#m4-tests)
- [M4: Not covered / deliberately skipped](#m4-not-covered--deliberately-skipped)
- [M5: Console (Fluent UI Blazor, auth modes, endpoint separation)](#m5-console-fluent-ui-blazor-auth-modes-endpoint-separation)
- [M6: Keys, namespaces and trust, certificates, playground, audit log, about](#m6-keys-namespaces-and-trust-certificates-playground-audit-log-about)
- [M7: Limits, fault injection, Prometheus metrics, structured log levels](#m7-limits-fault-injection-prometheus-metrics-structured-log-levels)
- [M8: `ekmmock` CLI, conformance suite, bench](#m8-ekmmock-cli-conformance-suite-bench)
- [M9 (1/2): Docker image, compose, health check, container-safe console binding, CI](#m9-12-docker-image-compose-health-check-container-safe-console-binding-ci)
- [M9 (2/2): Azure Bicep (VM and ACI), end-to-end script, README, RUNBOOK and RESULTS](#m9-22-azure-bicep-vm-and-aci-end-to-end-script-readme-runbook-and-results)
- [Security review follow-up](#security-review-follow-up)

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

## M1: AES Key Wrap (A256KW / A256KWP)

- **Question (spec 6.4, open question 8):** does the .NET version in use ship an AES Key Wrap API?
- **Finding (measured, .NET 10.0.14 runtime / SDK 10.0.403):** partly. `System.Security.Cryptography.Aes` has public
  `EncryptKeyWrapPadded`, `DecryptKeyWrapPadded`, `TryDecryptKeyWrapPadded` and `GetKeyWrapPaddedLength`, which are
  RFC 5649 (key wrap **with padding**). RFC 3394 exists only as non-public helpers (`Rfc3394Wrap/Rfc3394Unwrap`). A test
  (`Runtime_ShipsOnlyTheRfc5649PaddedKeyWrapApi_...`) pins this finding and fails if a later .NET adds a public RFC 3394 API.
- **Decision:**
  - `A256KWP` (RFC 5649) uses the runtime API, as spec 6.4 prescribes when one exists.
  - `A256KW` (RFC 3394) is implemented in `AesKeyWrap.cs` on `Aes.EncryptEcb/DecryptEcb` single-block operations. The integrity
    check uses `CryptographicOperations.FixedTimeEquals`; temporary buffers are zeroed.
  - An own RFC 5649 implementation is kept (`WrapPaddedReference`/`UnwrapPaddedReference`) only as an independent cross-check:
    the self-test runs both against the RFC vectors, and tests compare both for every key length 1..4096, for single-bit
    tampering and for random garbage input.
- **Test vectors:** RFC 3394 section 4.1-4.6 and RFC 5649 section 6 are hard-coded and were checked against the RFC text. Note
  that RFC 5649 section 6 uses a **192-bit** KEK, so those two vectors are proven at primitive level (and in the self-test) and
  cannot be loaded into the AES-256-only key store. For an engine-level A256KWP vector, a 256-bit-KEK vector produced by
  Python `cryptography` (`aes_key_wrap_with_padding`, a third implementation) is used. RFC 3394 section 4.6 (256-bit KEK, 256-bit
  data) is exercised through the engine with an imported KEK.
- **Layer boundary:** base64url is not handled in `EkmMock.Crypto` (M2). Unwrap length rules live in the engine and map to
  `InvalidCiphertext`: KW multiple of 8 and at least 24; KWP multiple of 8, 16 to 4104; RSA exactly k bytes. A256KW has no upper
  DEK limit (the spec gives none); the 16 KiB request-body limit in M2 bounds it.

## M1: Thread safety and instance pooling

- **Decision:** one small bounded pool per key (`InstancePool<T>`, about 40 lines) holding `Aes` or `RSA` instances that are built
  from cached key material. A caller rents an instance exclusively and returns it, so no instance is ever used concurrently.
  `Microsoft.Extensions.ObjectPool` is **not** used: the engine stays dependency free, and disposing a key's instances on destroy
  is simpler with an own pool.
- **Benchmark (throw-away console app, Release, Windows 10.0.26300, 8 logical cores, .NET 10.0.14; mean microseconds per
  operation; run once, indicative only):**

  | Operation | New instance per call | Pooled |
  |---|---|---|
  | AES-256 KWP wrap, 32 B, 1 thread | 22.6 | 11.6 |
  | AES-256 KWP wrap, 8 threads (wall per op) | 13.4 | 6.8 |
  | AES-256 KWP wrap, 16 threads (wall per op) | 9.1 | 9.1 |
  | RSA-2048 OAEP-256 unwrap, 1 thread | 1606 (key import alone: 1029) | 461 |
  | RSA-2048 unwrap, 8 threads (wall per op) | 366 | 192 |
  | RSA-4096 unwrap, 1 thread | 8346 (import alone: 3384) | 3351 |
  | RSA-4096 unwrap, 8 threads (wall per op) | 1653 | 1098 |

  RSA creation from PKCS#8 is the dominant cost, so pooling is clearly right for RSA. For AES the gap is small but
  pooling is never slower, and a single code path is simpler. The pool keeps at most `max(4, cores)` idle instances per key.
- **Concurrency model:** the key map is a `ConcurrentDictionary` (lock-free reads on the hot path); all mutations and file writes are
  serialised by one lock; per-key flags (enabled, expiry) are swapped as one immutable object; counters use `Interlocked`.
  A destroyed key's pool is disposed, and an in-flight request that loses the race gets `KeyNotFound`, never a result from
  zeroed material. A concurrency test (16 threads on pooled AES and RSA keys) checks round trips and exact counters.

## M1: Test stack (xUnit version)

- **Decision:** xUnit **v3** (`xunit.v3` 4.0.2) with Shouldly 4.3.0, `Microsoft.NET.Test.Sdk` 18.11.0 and
  `xunit.runner.visualstudio` 4.0.1, all pinned in `Directory.Packages.props`. v3 is the current stable line.
- **Consequence:** xunit.v3 4.x runs on Microsoft.Testing.Platform, and the .NET 10 SDK refuses `dotnet test` in the old VSTest
  mode for such projects. `global.json` therefore sets `"test": { "runner": "Microsoft.Testing.Platform" }`; `dotnet test
  EkmMock.sln` works unchanged. The test project is an executable (`OutputType Exe`), as v3 requires. The Test SDK and VSTest
  runner packages are referenced for IDE/VSTest tooling compatibility; the command line does not depend on them.
- FluentAssertions is not used (licence, spec section 3).

## M1: Key store file format

- `keystore.json`, one `keys` entry per key and a `tombstones` list, `version: 1`. `System.Text.Json` source generation
  (`KeyStoreJsonContext`), `snake_case`, enums as the lower-case strings `oct`/`rsa` and `generated`/`imported`, binary
  fields in standard base64, timestamps ISO 8601, `null`s omitted. The same naming is used for `namespaces.json`.
- Blob: AES-256-GCM under the master key, 12-byte random nonce per blob, 16-byte tag, AAD
  `ekmmock:v1:{namespace}:{name}:{type}:{size}` with type `oct`/`rsa`, so a blob cannot be moved to another name, namespace,
  type or size. RSA keys are stored as PKCS#8; AES keys as the raw 32 bytes. A test decrypts a blob independently using the
  documented AAD.
- **Known limitation (simulator):** the AAD binds identity only. `enabled`, `not_after` and the counters are plain metadata, so
  someone with write access to the file can re-enable a key or change its expiry. This does not expose key material.
- **Corrupt keys:** a blob that fails authentication (tampered file, wrong master key, bad base64) keeps its entry; the key is
  `Corrupt`, wrap/unwrap and metadata give `HsmUnavailable`, the other keys load normally. The blob is written back byte for byte
  on later saves. Entries whose name, namespace or type is unusable cannot be addressed; they are counted in
  `LoadReport.UnreadableEntries` and preserved in the file.
- **Wrong master key guard (addition to the spec):** if *every* stored key is `Corrupt`, `Create` and `Import` are refused
  (`HsmUnavailable`). Otherwise a run with a wrong master key would mix two master keys in one file and the new keys would become
  unreadable when the right key returns. `SetEnabled`, `SetExpiry` and `Destroy` still work on corrupt keys.
- **Destroy:** removes the blob, writes a tombstone (namespace, name, type, size, origin, created, destroyed-at, destroyed-by) and
  zeroes the in-memory material after the file is written. `Create`/`Import` on a tombstoned name throw `KeyNameReserved` unless
  `allowReuseOfDestroyedName` is set. `List()` also returns tombstones, with state `Destroyed`.
- **Writes:** temp file in the same folder, `Flush(true)`, rename over the target; owner-only mode on Unix; stale `*.tmp` files are
  removed at startup. Writes are serialised by a lock and rolled back in memory if the write fails. An unparsable or
  unknown-version file makes startup fail instead of being overwritten.
- **Usage counters** (wrap/unwrap counts, last used) are in memory and persisted lazily: a timer (default 30 s,
  `CounterFlushInterval`, `Zero` disables it), `Flush()` and `Dispose()`. They are never written on the request path. A crash can
  lose up to one interval of counter increments; key material and flags are always written immediately.

## M1: Master key provider

- `IMasterKeyProvider.GetMasterKey()` returns an opaque `MasterKey` (source, `IsThrowAway`; the bytes are `internal` and zeroed on
  dispose). Implementations: `EnvironmentMasterKeyProvider` (`EKMMOCK_MASTER_KEY` base64 or `EKMMOCK_MASTER_KEY_FILE`, reader
  injectable so tests never touch real environment variables), `FileMasterKeyProvider`, `ExplicitMasterKeyProvider` (tests,
  embedding) and `ThrowAwayMasterKeyProvider` (explicit dev mode).
- Missing key throws `MasterKeyUnavailableException` and the backend constructor refuses to start (nothing is written). Both
  variables set is ambiguous and refused. A configured but malformed key (bad base64, not 32 bytes) is refused even in dev mode, so a
  typo never silently turns into a throw-away key. Error messages never echo the input.
- Dev mode creates a random key per process and exposes `SoftwareCryptoBackend.IsMasterKeyThrowAway` so the console can show the
  red banner; keys written under it are unreadable (`Corrupt`) after a restart, as intended.
- `MasterKey.GenerateBase64()` is what `ekmmock init` will print once; it returns a `string`, so the byte-type leak test does not
  flag it (see "Leak boundary" below).

## M1: Engine error model, import gating and leak boundary

- All engine failures are `EkmEngineException` with an `EkmErrorKind` whose names equal the EKM `ProxyError.code` values
  (`KeyNotFound`, `KeyDisabled`, `KeyExpired`, `UnsupportedAlgorithm`, `InvalidCiphertext`, `HsmUnavailable`, `InvalidKeyName`, ...),
  plus engine-only kinds (`InvalidInput`, `KeyAlreadyExists`, `KeyNameReserved`, `OperationNotAllowed`, `InternalError`). M2 maps kind
  to HTTP status in one place. Messages are fixed strings per kind, never include input, key material or inner exceptions.
- Check order for wrap/unwrap: engine available, key exists, key healthy (corrupt or failed self-test gives `HsmUnavailable`),
  algorithm matches key type and passed self-test (`UnsupportedAlgorithm`), enabled (`KeyDisabled`), not expired (`KeyExpired`), then
  input rules (`InvalidInput` for wrap, `InvalidCiphertext` for unwrap). `GetMetadata` still works for disabled/expired keys and
  returns `null` only for unknown or destroyed keys.
- Import (`IKeyManager.Import`) is off unless `SoftwareCryptoBackendOptions.AllowKeyImport` is set;
  `IsKeyImportEnabledInEnvironment` reads `EKMMOCK_ALLOW_KEY_IMPORT=true`. AES import takes 32 raw bytes, RSA takes PKCS#8
  (2048/3072/4096, exponent 65537).
- **Leak boundary:** a reflection test walks every public type and fails if any public member returns `byte[]`, spans, memory,
  `RSAParameters`, `RSA`, `Aes`, streams, etc., except an explicit allow-list (wrap/unwrap outputs and the RSA public `n`/`e`).
  `MasterKey.GenerateBase64()` returns a `string` and is not caught by that type check; it is intentional (init command).
  `RsaPublicKey` has a JSON converter (`{"n","e"}` base64url) so `KeyInfo` can be serialised without touching anything but public numbers.

## M1: Namespaces

- A namespace is `Name` + `Prefix` + `ClientTrust` (exact, case-sensitive subject CNs and root CA certificates as base64 DER).
  The property names match the `SeedNamespaces` section of appsettings. Prefixes are normalised (leading and trailing slashes
  removed), at most 64 characters, `[A-Za-z0-9/-]`, no empty segments. Only `_default` may have the empty prefix, and `_default`
  must have it. Names are `[A-Za-z0-9_-]{1,64}`; key names `[A-Za-z0-9-]{1,64}` (hand-written check so a trailing newline cannot
  sneak through the `$` anchor).
- `NamespaceResolver.Resolve` is a pure function: longest prefix on whole path segments, case-sensitive, a single trailing slash
  tolerated, `//` rejected. It returns the namespace and the remaining segments; M2 decides whether they form `info` or
  `{key}/{op}` (otherwise 404). With `_default` defined, an unknown prefix lands in `_default` and becomes a 404 at that step.
- `NamespaceStore` keeps an immutable snapshot (lock-free reads), persists to `namespaces.json` atomically before publishing, and
  seeds from configuration only when the file does not exist. Keys are stored by namespace *name* and are independent of the
  namespace definitions (removing a definition does not delete keys).
- `TrustImporter` parses (no UI, no persistence) the `az keyvault ekm-connection certificate show` JSON (`caCertificates` base64
  DER, `subjectCommonName`; camelCase or snake_case, entries may also be PEM) and PEM text, and returns per-certificate
  subject/issuer/validity/SHA-256 thumbprint for the review step. The exact shape of the real Azure output is assumed from the spec
  and Learn wording and should be confirmed against a real Managed HSM.

## M1: Build and repository conventions

- `Directory.Build.props`: net10.0, C# latest, nullable, implicit usings, warnings as errors, `AnalysisLevel latest`, invariant
  globalization. `Directory.Packages.props` pins every package centrally. `EkmMock.Crypto` has **no** package or framework
  reference beyond the BCL (a test asserts it references no ASP.NET Core, `Microsoft.Extensions.*` or third-party crypto assembly).
  `InternalsVisibleTo` is granted to `EkmMock.Crypto.Tests` only.
- The solution uses the classic `.sln` format (`dotnet new sln --format sln`).

## M2: EKM request pipeline and host composition

- **Project:** `src/EkmMock.Server` (Web SDK, Minimal-API host, no controllers, no ProblemDetails, no Kestrel/TLS code). `Program.cs` is
  four lines plus `public partial class Program` for `WebApplicationFactory<Program>`; all wiring lives in
  `Hosting/EkmServerServiceCollectionExtensions` (`AddEkmMockServer` for the host, `AddEkmMockServices` for the services) and
  `Ekm/EkmPipeline` (`UseEkmPipeline`). Everything except `Program` is `internal` (`InternalsVisibleTo EkmMock.Server.Tests`).
- **Pipeline (spec 7), as built:** `Exchange → Route → [Faults M7] → [Auth M3] → [Limits M7] → Dispatcher → ICryptoBackend`.
  `Exchange` creates the `EkmRequestContext` feature, is the global safety net and writes the log line. `[RequestCapture M4]` goes
  *in front of* `Exchange` so rejected requests are captured too. **Clarification of spec 7:** routing (namespace, op, key) is resolved
  right after capture and before Faults/Auth, because both need the namespace (and faults the op and key). An unroutable path is
  therefore `404 NotFound` before authentication; a client cannot be authenticated for an unknown namespace anyway.
- **Why a branch and a terminal delegate instead of endpoint routing:** spec 4.2 forbids template routes for the prefix. The EKM
  branch is `UseWhen(EkmPipeline.IsEkmRequest, …)`; in M2 the predicate is `true`, M5 narrows it to the EKM listener
  (`HttpContext.Connection.LocalPort`) and gives the console port its own branch. The last stage is one delegate that calls
  `EkmDispatcher`; per-operation handlers are plain methods on `EkmHandlers`. Nothing outside the branch handles EKM paths.
- **`EkmRequestContext`** (feature on `HttpContext`, `ctx.GetEkmContext()`): exchange id (sequential from 1), connection id, received
  at, route (namespace/op/key), api-version, `request_id`/`correlation_id`/`pool_name` (each capped at 256 chars), alg, request body
  size, status, error code, crypto time, total time, unexpected exception type. It never holds `value`, bodies or headers. M4 (inspector),
  M3 (client CN) and M7 (faults, limits) extend it.
- **Engine availability seam:** `IEngineAvailability.IsAvailable` (default: startup finished and `ICryptoBackend.IsAvailable`).
  `info` and every key operation answer `503 HsmUnavailable` when it is false; M7's "HSM offline" fault replaces or decorates it.
  A corrupt key does not make the engine unavailable: `info` stays 200 and only that key's operations (metadata, wrap, unwrap) are 503
  (spec 14 test 19; proven with a wrong master key).
- **Startup (`EkmStartupService`, a hosted service, so it runs before the server accepts traffic; observed with a real Kestrel run):**
  listener guard, open key store (constructing `SoftwareCryptoBackend` throws `MasterKeyUnavailableException` without a master key, so the
  host refuses to start and writes nothing), open namespaces (seeded from `SeedNamespaces` only if `namespaces.json` does not exist),
  optional sample keys, startup self-test (`SelfTest:Strict` makes a failed self-test fatal), then `EkmStartupState.MarkReady`. Until
  ready the engine reports unavailable.
- **Master key and secrets:** `IMasterKeyProvider` defaults to M1's `EnvironmentMasterKeyProvider` (`EKMMOCK_MASTER_KEY` /
  `EKMMOCK_MASTER_KEY_FILE`), read straight from the environment, never from `IConfiguration`; `appsettings.json` has no secret and a test
  guards that. Tests replace the provider through DI. `EKMMOCK_ALLOW_KEY_IMPORT=true` is read once into the backend options.
- **`--dev`:** the flag sets `Dev:Enabled=true` (in-memory configuration, highest precedence). Effects: a missing master key becomes a
  throw-away one (`SoftwareCryptoBackend.IsMasterKeyThrowAway`, logged as a warning now, a red console banner in M5) and, since M3, a missing
  `Tls:CertFile` becomes a generated throw-away `localhost` certificate (flagged, see "M3: Server certificate"). It never relaxes TLS or
  authorization. `Dev:SeedSampleKeys=true` (default false, also off in the shipped `appsettings.json`) creates `aes-key-1` (AES-256) and
  `rsa-key-1` (RSA-2048) in `_default` if they do not exist (including as tombstones); they are created before the self-test, which then covers them.
- **No plain HTTP on a real port (resolved in M3):** in M2 the server configured no listener and `PlainHttpGuard` refused to start on a real
  network server outside `--dev`. M3 replaced the guard with the real TLS 1.3 + mTLS listener (see "M3: ..." below); there is no plain-HTTP
  mode at all, and the real-Kestrel tests cover chunked bodies, oversize bodies and percent-encoded paths that M2 had verified by hand.
- **Configuration (`appsettings.json`, spec 16):** `ProxyInfo`, `Data:Path`, `SeedNamespaces`, `SelfTest:Strict`, `Dev`, plus the `Endpoints`
  placeholder. Bound to `ProxyInfoOptions` (validated on start: no empty value), `DataOptions`, `SelfTestSettings`, `DevOptions`,
  `SeedNamespaceOptions`. `Data:Path` defaults to `/data` as in the spec; tests always override the folder (`PostConfigure`), so no test can
  write there. `Limits`, `Inspector`, `Console`, `Tls` arrive with their milestones.
- **Logging:** `ILogger` with the built-in JSON console formatter (UTC timestamps, no scopes). One `EkmMock.Exchange` line per request with the
  spec 9 fields that exist now: `exchange_id, request_id, correlation_id, pool_name, namespace, op, key, alg, status, error_code,
  duration_ms, crypto_ms` plus `exception_type` (type name only, set for unexpected failures, level Error). Missing until M3/M7:
  `client_cn`, `injected_delay_ms`, and the 150/250 ms warning/error thresholds (M7). The logged `alg` is the supported name or the literal
  `unsupported` (client text is never logged), `key` is cut to 80 characters. A test proves that no DEK, key material, master key, `value`,
  `n`, `e` or body reaches the log.

## M2: EKM validation order (ordered-check table)

The first failing check answers; later checks are never reached. Implemented in `EkmRouteMiddleware` (1) and `EkmDispatcher` (2 to 9).
URL level checks come before anything is read from the body, so a bad URL never costs a body read.

| # | Check | Failure | Status / `code` |
|---|---|---|---|
| 1 | Path resolves to a namespace (longest whole-segment prefix, case-sensitive, one trailing slash tolerated, no empty segments) and the rest is exactly `info` or `{key}/{metadata\|wrapkey\|unwrapkey}` | unknown prefix, unknown op, extra segments | 404 `NotFound` |
| 1a | *(M7 Faults, M3 Auth, M7 Limits slot in here)* | | |
| 2 | Method is exactly `POST` (case-sensitive; response has `Allow: POST`) | any other method | 405 `MethodNotAllowed` |
| 3 | `api-version` query parameter present exactly once and equal to `0.1-preview` (case-sensitive) | missing, empty, repeated, other | 400 `UnsupportedApiVersion` |
| 4 | Key operations: key name matches `^[A-Za-z0-9-]{1,64}$` (`EkmNames.IsValidKeyName`) | any other name | 400 `InvalidKeyName` |
| 5 | `Content-Type` is `application/json` (case-insensitive, optional `charset=utf-8`) | missing, other type, other charset | 400 `InvalidRequest` |
| 6 | Body at most 16 KiB (checked on `Content-Length` and while reading, so chunked bodies are covered) | larger | 400 `InvalidRequest` |
| 7 | Body is one JSON object (valid UTF-8, optional BOM, no comments, no trailing commas, no trailing content, depth at most 32) | anything else, empty body | 400 `InvalidRequest` |
| 8 | `request_context` present as a JSON object (`request_id`, `correlation_id`, `pool_name` optional) | absent, null or not an object | 400 `InvalidRequest` |
| 9 | Engine available (`IEngineAvailability`) | store not loaded, backend disposed, later the HSM-offline fault | 503 `HsmUnavailable` |
| 10 | `info`: answer 200. `metadata`: `GetMetadata` | unknown or destroyed key; corrupt key | 404 `KeyNotFound`; 503 `HsmUnavailable` |
| 11 | Wrap/unwrap syntax: `alg` is a string and present; `alg` is one of the four names (case-sensitive); `value` is a string and present; `value` is strict base64url | missing or mistyped; unknown alg; bad base64url | 400 `InvalidRequest`; 400 `UnsupportedAlgorithm`; 400 `InvalidRequest` |
| 12 | Engine order (M1): key exists, key healthy, alg matches key type, key enabled, key not expired, input rules | unknown key; corrupt key; alg/key-type mismatch; disabled; expired; wrap input rule; unwrap length or integrity failure | 404 `KeyNotFound`; 503 `HsmUnavailable`; 400 `UnsupportedAlgorithm`; 403 `KeyDisabled`; 403 `KeyExpired`; 400 `InvalidRequest`; 400 `InvalidCiphertext` |

Reasoning for the order: syntax before state (a malformed request is a 400 whatever the key's state), and 404/403/503 from the engine only
for syntactically valid requests. `info` and `metadata` ignore a mistyped `alg`/`value` like any other unknown field; only wrap and unwrap
reject it. The order is pinned by `ValidationOrder_IsRoute_Method_ApiVersion_KeyName_ContentType_Body_RequestContext_Engine` and the
two tests next to it.

## M2: EKM error mapping (one place)

- **Location:** `src/EkmMock.Server/Ekm/ProxyErrors.cs` only. `ProxyErrors.StatusOf` is the status per wire code (spec 4.4),
  `ProxyErrors.FromEngine(EkmErrorKind)` the single engine-kind to wire-code mapping, `ProxyErrors.Map(Exception, op)` the safety net used by
  `EkmExchangeMiddleware`. A test fails if any other server source file mentions `EkmErrorKind.`, and another maps every enum member
  (a new engine kind makes the exhaustive test fail until the table is extended deliberately).
- **Table:** `KeyNotFound` 404; `KeyDisabled`, `KeyExpired`, `OperationNotAllowed` 403; `UnsupportedAlgorithm` 400; `InvalidInput` 400
  `InvalidRequest`; `InvalidCiphertext` 400; `HsmUnavailable` 503; `InvalidKeyName` 400; `KeyAlreadyExists`, `KeyNameReserved`,
  `InternalError` 500 `InternalError` (cannot arise from an EKM request; management-only kinds). Protocol-level codes: `InvalidRequest`,
  `InvalidKeyName`, `UnsupportedApiVersion` 400; `Unauthenticated` 401 (M3); `NotFound` 404; `MethodNotAllowed` 405; `TooManyRequests` 429 (M7).
- **Messages:** fixed literals, never exception text, input, key names or key material. `KeyDisabled`/`KeyExpired` use Learn's wording
  ("Operation WrapKey is not allowed on a disabled key"). Anything unexpected is `500 InternalError` / "An internal error occurred"; the log gets
  the exception *type name* only. `BadHttpRequestException` (host-level rejections) is `400 InvalidRequest`. A client that disconnects
  mid-request is logged as status 499 and nothing is written.
- **Decisions where the spec is silent:** the `405` code is `MethodNotAllowed` (spec 4.1 gives the status but no code; open question 9). An
  unknown prefix, unknown operation and extra segments all use `NotFound`; `KeyNotFound` is reserved for a missing key.
- **Failed unwrap** (wrong key, tampered or random input, wrong OAEP variant) is always `400 InvalidCiphertext`: tested by flipping every byte
  of AES wrapped values and several of RSA ones.

## M2: Base64url (answer to open question 7)

- **Finding (measured on .NET 10.0.14, pinned by tests `OQ7_*`):** `System.Buffers.Text.Base64Url` decoding **accepts padded and unpadded**
  input (`AQ`, `AQ==`, `AQA=`), rejects `+` and `/`, rejects non-canonical trailing bits (`AB`) and malformed padding, **but silently skips
  whitespace** (`"AQ A"` and `"AQ\n"` are valid for the runtime). So no padding normalisation is needed, but strictness must be added.
- **Decision:** `Base64UrlCodec.TryDecode` pre-scans the UTF-8 input: only `A-Z a-z 0-9 - _`, optionally followed by one or two `=` that
  make the total length a multiple of four, and a length that is not 1 mod 4; then it calls the runtime decoder. Whitespace, `+`, `/`, an
  inner `=`, non-ASCII, wrong padding and non-canonical bits are all `400 InvalidRequest` ("The value field is not valid base64url").
  Output is always `Base64Url.EncodeToUtf8` (never padded). `n`/`e` use `RsaPublicKey` (M1, minimal big-endian) encoded the same way; 65537 is `AQAB`.
- Empty `value` decodes to zero bytes and is then judged by the engine (wrap: `InvalidRequest`, unwrap: `InvalidCiphertext`).

## M2: JSON and secret handling

- **Source generation:** `EkmJsonContext` (`JsonNamingPolicy.SnakeCaseLower`, nulls omitted) serialises `ProxyError`, `ProxyInfoResponse` and
  `KeyMetadataResponse`; the project sets `JsonSerializerIsReflectionEnabledByDefault=false`, so reflection serialisation cannot creep in.
- **Requests are parsed by hand with `Utf8JsonReader`** (`EkmRequestBody`) and the `{"value":"…"}` responses are written by hand, so a DEK is
  never a `string` (strings cannot be zeroed). The body is read into a rented buffer; `value` stays a UTF-8 slice of it (or a second rented buffer
  when the JSON string contains escapes such as `\u002d`, which is legal JSON); it is decoded into a rented buffer, passed to the engine
  as a span, and every buffer touched (request, decoded DEK, unwrap plaintext, response) is wiped with
  `CryptographicOperations.ZeroMemory` before it returns to the pool. Unknown fields are skipped; duplicate fields: the last wins (as
  `System.Text.Json` does). A concurrency test (24 tasks, distinct DEKs) proves pooled buffers are never mixed up. Limits of managed memory
  still apply (copies made by the runtime or the GC cannot be wiped); the README will say so in M9.
- `request_id`, `correlation_id`, `pool_name` of a non-string type are ignored (they are correlation aids only); a mistyped `alg` or
  `value` is rejected by wrap/unwrap only.
- Crypto is called synchronously on the request thread (no `Task.Run`); only HTTP I/O is awaited.

## M2: Learn comparison

The Microsoft Learn "EKM Proxy API reference" (`0.1-preview`, read on 9 November 2026) agrees with the implemented contract: POST only
(`POST https://{server}/[path-prefix]/info|{key-name}/metadata|wrapkey|unwrapkey?api-version=0.1-preview`), `Content-Type: application/json`,
`request_context` with `request_id` (optional), `correlation_id`, `pool_name`; ProxyError `{code, message}` with statuses 400/401/403/404/429/5xx
and the example `KeyDisabled` / "Operation WrapKey is not allowed on a disabled key"; key types `oct` 256 and `RSA` 2048/3072/4096; `key_ops`
exactly `["wrapKey","unwrapKey"]`; `n`/`e` as base64url of the unsigned big-endian bytes with `AQAB` for 65537; algorithms `A256KW`, `A256KWP`,
`RSA-OAEP-256`, `RSA-OAEP`; key name `[A-Za-z0-9-]` up to 64 and prefix `[A-Za-z0-9/-]` up to 64. The Learn example values were used as test data
(the 32 byte DEK wraps to 40 bytes, 54 unpadded characters). **No conflict was found** that stops work. Items Learn leaves open are
recorded in OPEN-QUESTIONS.md (items 1, 9 to 14).

## M2: Not covered / deliberately skipped

- **No latency test for `info` (p99 < 5 ms).** In-process timings are dominated by test-host and JIT noise and would be flaky next to the
  parallel RSA tests; real benchmarks belong to M4/M7. A manual real-Kestrel run showed 0.2 to 0.4 ms for warm `info` calls (single samples,
  not a measurement).
- **Chunked bodies** are tested in the test host as bodies without a `Content-Length` (and by hand against real Kestrel with
  `Transfer-Encoding: chunked`: a 20 KB body gave the 400 ProxyError, a small one 200). Automated in M3 (`KestrelLimitsTests`).
- **Percent-encoded slashes:** the test host decodes `%2F` in the path, real Kestrel does not. A key name containing `%2F` is
  `400 InvalidKeyName` on real Kestrel and a routing 404 in the test host. M3 automated the real-Kestrel case
  (`APercentEncodedSlashInTheKeyName_IsInvalidKeyName_OnRealKestrel`, open question 16 answered).

## M3: Where the code lives

- **New project `src/EkmMock.Pki` (BCL only, no ASP.NET, no third-party crypto):** `CertificateAuthority` (self-signed root, intermediate,
  server and client certificates with basicConstraints, keyUsage, serverAuth/clientAuth EKU, SAN, SKI/AKI, RSA 2048 or ECDSA P-256) and
  `IssuedCertificate` (certificate + PKCS#8 key PEM + chain PEM, `WriteFiles`). It is the logic behind M8's `ekmmock certs` and the console's
  "generate test root CA + server certificate" action, and the dev certificate of `--dev`. Chosen over putting it into `EkmMock.Crypto` (that
  is the HSM engine, and must stay free of anything that is not the engine) and over `EkmMock.Server` (the CLI would then depend on the web
  host). Spec 16 lists no such project; it is a deliberate, small addition.
- **New project `tests/EkmMock.TestSupport`:** `TestPki` (a server CA, two trusted client CAs, one untrusted client CA), `TempFolder`,
  `DistinguishedNames`. Shared by the server tests now and by the console/CLI tests later. It has no test framework reference.
- **Server layout:** `Tls/` (server certificate provider and snapshot, client trust provider, handshake validator, TLS policy, CN reader, options),
  `Connections/` (events, sink, store, metrics, ClientHello parser and tap, connection state, capture middleware), `Hosting/EkmKestrel.cs`
  (the only place that configures listeners, `UseHttps` and `ClientCertificateMode`; an architecture test pins that), `Ekm/EkmAuth.cs`.
  `Program.cs` calls `EkmServerServiceCollectionExtensions.BuildEkmMockApp`, which tests also use (with a `customize` hook for temp folders and
  ephemeral ports). It has no switch for plain HTTP or disabled authorization.

## M3: TLS stack (spec 5.1)

- **Listener:** `Endpoints:Ekm:Url` (default `https://0.0.0.0:8443`; `https` is required, `*`, `localhost`, IPv4/IPv6 literals and port `0` are
  accepted). `HttpsConnectionAdapterOptions`: `SslProtocols = Tls13`; `ClientCertificateMode = AllowCertificate`; `ClientCertificateValidation`
  = `ClientCertificateValidator.Validate`; `ServerCertificateSelector` = the hot-reload provider; `HandshakeTimeout` = `Tls:HandshakeTimeout`
  (default 10 s); protocols `Http1AndHttp2` (ALPN negotiates `h2` or `http/1.1`; both proven on the real listener). `OnAuthenticate` sets the
  cipher suites (below) and swaps the selection callback for `ServerCertificateContext` so the TLS stack sends the **intermediates** of the
  configured chain (built offline from the PEM file); the selector stays as the contract Kestrel requires. `AddServerHeader = false`.
- **Cipher suites and the Windows caveat.** `TLS_AES_256_GCM_SHA384` and `TLS_AES_128_GCM_SHA256` are set through `CipherSuitesPolicy` in
  `OnAuthenticate`. `CipherSuitesPolicy` throws `PlatformNotSupportedException` on Windows (the probe in `TlsPolicy` catches exactly that, so
  support is detected, not assumed from the OS name). Where it is unsupported: a **warning at startup** names the limit, TLS 1.3 is still
  enforced, and a **post-handshake check** (`ConnectionCapture.EvaluatePolicy`, run by the connection middleware after TLS) closes any
  connection that negotiated another protocol or suite and records it as `cipher_suite_not_allowed`. Measured on Windows 11 (SChannel): the
  negotiated suite is reported (`NegotiatedCipherSuite`) and was always `TLS_AES_256_GCM_SHA384`, so the check works there, but it cannot be
  exercised with a real client (Windows clients cannot restrict suites either); `EvaluatePolicy` is therefore unit-tested directly.
  This is a weaker guarantee than refusing in the handshake (the client sees an accepted handshake and then a closed connection), and the
  honest statement for the About page is "not enforceable by the TLS stack on this OS". `TlsPolicy.Effective` (`EffectiveTlsPolicy`: protocol,
  permitted suites, `CipherSuiteEnforcement`, summary text, OS) is the **About-data seam**; together with `IServerCertificateProvider.Info` /
  `LastError` it holds everything the console's About and Certificates pages need. Production runs on Linux/OpenSSL where it is enforced:
  **verified in a `mcr.microsoft.com/dotnet/sdk:10.0` Linux container** (a client offering only ChaCha20 is refused with
  `no_common_cipher_suite`, one offering ChaCha20 + AES-256 gets AES-256, one offering only AES-128 gets AES-128).
- **TLS session resumption is disabled** (`AllowTlsResume = false` in `OnAuthenticate`). Client-certificate validation is the only access control
  (spec 2), and a resumed TLS 1.3 session skips the handshake validation, never delivers the intermediates the client sent, and keeps whatever
  identity the original session authenticated. Every connection therefore gets a full handshake (one round trip in TLS 1.3 either way;
  Managed HSM reuses keep-alive connections), the union validation and the capture of the presented chain run for every connection, and
  `ConnectionEvent.Resumed` is reported as `false`. Authorization (per request, per namespace) would have re-validated a resumed certificate in any
  case; this removes the dependence on how each OS handles a resumed session. **Honest note on the trigger:** during M3 an intermittent failure
  appeared in 2 of 15 full-suite runs on Windows (never in isolation, never on Linux): a request that carried *no* client certificate was
  authorized as the test client identity (`StatusCode 200/404` instead of `401`, in two adjacent tests of one class). Resumption of a session that
  had authenticated another certificate was the only mechanism found that fits, so it was disabled; but it could **not** be reproduced as the cause
  (400 alternating raw connections with and without a certificate, resumption on, produced no mix-up), so the cause is not proven. After the change
  the suite ran green repeatedly (see the M3 report); the tests that would show a recurrence now print the exchange log and the handshake events.
  See `EveryNewConnection_GetsAFullHandshake_WithTheClientCertificateValidatedEachTime` and `AClientWithoutACertificate_IsNeverServedAsAnEarlierClient_AcrossManyNewConnections`.
- **Kestrel's validation callback is not replaceable per connection.** Kestrel passes its own callback to the `SslStream` constructor, and
  setting `RemoteCertificateValidationCallback` in `OnAuthenticate` throws ("already set in the SslStream constructor"; found the hard way).
  So the handshake verdict is attached to its connection through an `AsyncLocal<ConnectionState>` set by the capture middleware that awaits the
  handshake (the validation callback runs synchronously inside that flow). Kestrel itself still owns "no certificate proceeds".
- **Windows only: ephemeral keys.** A certificate loaded from PEM has an ephemeral key that SChannel cannot serve. The loader (and the PKI
  library) re-imports the PFX bytes into a regular key container; harmless on Linux. Also on Windows, the TLS stack caches CA certificates it
  sees in the current user's `CurrentUser\CA` store; with equal CA names that makes chain building ambiguous (observed: "unknown chain building
  error" and `NotSignatureValid` against stale test roots). The tests therefore give every CA a unique name and remove what they left behind
  (`TestPki.Dispose`); the dev-mode root CA name carries a random suffix. It is OS behaviour, not something EkmMock does.
- **Kestrel limits (spec 4.1, 5.5):** `RequestHeadersTimeout` 2 s, `KeepAliveTimeout` 120 s, keep-alive on, `MaxRequestBodySize` 16 KiB. These are
  server-wide Kestrel limits (there is no per-endpoint limit); the console (M5) raises its own via `IHttpMaxRequestBodySizeFeature`. Oversized
  bodies still get **our** `400 InvalidRequest` ProxyError, never Kestrel's 413: a `Content-Length` over 16 KiB is refused by the handler before
  the body is read (proven with a 5 MB announcement on a raw socket and with 20 000 bytes), chunked bodies too. Kestrel counts chunk framing against
  its limit, so a chunked body of exactly 16384 bytes may be refused (then as the same ProxyError 400); a `Content-Length` body of exactly 16384 is
  accepted and 16385 is refused. A client that keeps sending a huge body after the 400 may see the connection reset before it reads the answer
  (TCP behaviour; Managed HSM bodies are well under 1 KiB). Slow request headers: the connection is closed after the 2 s timeout (tested).

## M3: Client certificate validation and authorization (spec 5.1)

- **Two stages, on purpose.** *Handshake* (`ClientCertificateValidator`): the namespace is not known yet, so the chain is built against the
  **union of every namespace's root CAs** with `TrustMode = CustomRootTrust` (the OS trust store is never consulted), `RevocationMode = NoCheck`,
  `DisableCertificateDownloads = true` (no AIA fetch, nothing leaves the process), and `VerificationFlags = IgnoreNotTimeValid`. It returns false
  (handshake fails, reason `client_cert_not_trusted` with the chain status flags) when the chain does not build. No certificate: the handshake
  proceeds. *Authorization* (`MtlsCallerAuthorizer`, the Auth slot after Route): the chain is built again against **that namespace's own roots**,
  with `VerificationTime = now` and the application policy `clientAuth` (so validity and EKU **are** judged here), and then the CN is compared.
- **Validity (the decision the brief asked for):** an expired or not-yet-valid client certificate passes the handshake and gets a **401** with the
  reason (`CertificateExpired` / `CertificateNotYetValid`) in the log line and on the request context. Rejecting it in the handshake would give the
  operator an opaque TLS failure and no captured exchange. The check covers the leaf and every chain element. An expired certificate is therefore
  never authorized; it is only refused one stage later. Revocation is not checked (nothing to check against; Managed HSM publishes no CRL for it).
- **EKU:** if the certificate carries an EKU it must include `clientAuth`; a certificate without any EKU extension is accepted (X.509: valid for all
  purposes). Not checked at the handshake (a wrong EKU is a 401, not a handshake failure).
- **CN rule (exact, case-sensitive, parsed):** the CN comes from the ASN.1 distinguished name (`X500DistinguishedName.EnumerateRelativeDistinguishedNames`),
  never from the formatted `Subject` string, so commas, plus signs, quotes and backslashes inside a value cannot change what is compared. The
  subject must contain **exactly one** CN attribute, in a single-valued RDN; no CN, two CNs, or a CN inside a multi-valued RDN is ambiguous and is
  refused (`CommonNameMissingOrAmbiguous`). The comparison is ordinal against the namespace's list: no wildcard, no substring, no case folding, no
  trimming (tested with 7 near-miss names, an escaped `pool, one+two`, a two-CN subject and an ASN.1 multi-valued RDN).
- **Intermediates:** the certificates the client sent are captured at the handshake (at most 8) and added to the **ExtraStore** (never to the trust
  anchors) when the chain is rebuilt per namespace. A client that does not send its issuing CA is not authenticated.
  **Limit (identical on Windows and Linux, pinned by a test):** custom root trust anchors only at **self-signed roots**. A namespace that lists an
  *issuing* CA in `caCertificates` instead of the root authenticates nobody. The Learn reference says `caCertificates` are root certificates, so this
  matches the contract; the M6 trust import should warn about a non-root entry.
- **Defence in depth:** if the connection's handshake recorded a client certificate (or none) and the request sees a different one, the request is
  refused (`ClientCertificateChanged`, 401, unit-tested with hand-made connection features). It protects against any path by which the certificate
  attached to a request could differ from the one the handshake validated; see the note on the intermittent test failure under "M3: TLS stack".
- **Per-request, against the current trust:** authorization runs on every request, so removing a CA or a CN from a namespace locks out an
  already open connection on its next request (401), and the handshake union refuses new connections at once (`RuntimeTrustTests`).
- **Unauthenticated callers learn nothing:** Auth runs before everything but routing, so with no or a wrong certificate an unknown key, a bad
  `api-version`, a wrong method or a broken body are all `401`, not `404`/`400` (tested). The 401 body is always `Unauthenticated` /
  "Authentication failed"; the reason is internal (`auth_failure` in the log, `EkmRequestContext.Authentication` for the inspector).
- **Captured for M4 on the request context (`EkmAuthResult`):** certificate present, subject, issuer, serial, SHA-256 thumbprint, not-before/after,
  chain result (status flags), CN allowed, namespace matched, failure reason; `EkmRequestContext.Connection` links the exchange to its
  `ConnectionState` (TLS version, suite, ALPN, handshake time, request count). The exchange log line gained `client_cn` and `auth_failure`.
- **No bypass:** the authorizer and the port policy are DI services (`IEkmCallerAuthorizer`, `IEkmPortPolicy`). The only replacement is the in-process
  test host of the M2 handler tests (`AllowAllCallerAuthorizer`, `AnyPortPolicy`, defined in the **test** assembly). An architecture test asserts the
  production assembly has no allow-all type, no "disable auth/plain HTTP" option property, an https-only shipped configuration, an https-only URL
  parser, and that the production composition resolves `MtlsCallerAuthorizer` and `EkmListenerPorts`.
- **Trust snapshot refresh (`ClientTrustProvider`):** the namespace store publishes a new immutable list on every change, so a changed list
  reference means changed trust. The next caller rebuilds the snapshot (union store + per-namespace sets) and swaps it with a compare-and-swap; a
  racing loser is disposed; a retired snapshot is disposed after 30 s because a validation that started before the swap may still use it. No
  timer, no event, no stale window, no change to M1's `NamespaceStore` (an event would add nothing M6 cannot get from the list reference).
  `Chain`/`X509Chain` objects are created per validation and disposed with `using`.

## M3: Port separation (spec 5.4)

- `EkmPipeline.UseEkmPipeline` branches on `HttpContext.Connection.LocalPort` with `IEkmPortPolicy`. `EkmListenerPorts` is filled by the EKM
  listener's own connection middleware (every EKM connection registers its local port before any request) and seeded with the configured port, so
  ephemeral listeners work and **no other listener can claim an EKM port**. Everything on another port gets a plain `404` (M5 puts the console
  pipeline there); on the EKM port anything that is not an EKM route is the EKM-style `404 NotFound` ProxyError (`/api/console/keys`, `/metrics`,
  `/healthz`, `/readyz`, `/`, `/_blazor`: tested). A plain-HTTP Kestrel listener added next to the EKM endpoint answers EKM paths with 404 and
  never reaches a handler (key usage counters and exchange log lines unchanged, tested). Routing precedes Auth, so a request for a path no
  namespace claims is a 404 even without a certificate (see open question 22).

## M3: Connection capture (spec 7, 8.2, 14 test 21)

- **Shape.** Two Kestrel connection middlewares on the EKM `ListenOptions`: `Outer` **before** `UseHttps`, `Inner` **after** it. `Outer` records
  *opened*, wraps the transport with a passive tap, awaits the rest of the pipeline and, when it returns, publishes *handshake failed* (if `Inner`
  never reported success) and *closed* (duration, requests). `Inner` only runs when TLS succeeded: it reads `ITlsHandshakeFeature` (protocol,
  `NegotiatedCipherSuite`, SNI) and Kestrel's `ISslStreamFeature` (ALPN), publishes *handshake succeeded* with the client certificate summary and
  the handshake time, and applies the post-handshake cipher policy.
- **Why not catch the exception:** Kestrel's `HttpsConnectionMiddleware` swallows handshake exceptions (debug log, closes the connection), so
  nothing propagates to a wrapper; "closed without `Inner` having run" is the reliable signal. Parsing the debug log was rejected: its text and
  event ids are internal, and the OS error text differs between SChannel and OpenSSL.
- **Reason classification uses facts, not OS messages.** The tap copies the first TLS record (at most 16 KiB, no consumption, no delay, buffer
  returned to the pool as soon as the hello is decided) and `ClientHelloParser` reads the ClientHello: offered versions (`supported_versions`, else
  the legacy version), cipher suites, SNI, ALPN. Precedence (`ConnectionCapture.Classify`): (1) post-handshake policy violation; (2) the
  handshake verdict of the client certificate (`client_cert_not_trusted`, with the chain status flags); (3) from the hello: `not_tls` (not a handshake
  record: plain HTTP to the TLS port, port scans), `tls_version_not_supported` (TLS 1.3 not offered; the detail names what was offered, e.g.
  "client offered TLS 1.2"), `no_common_cipher_suite` (TLS 1.3 offered but neither permitted suite; the detail names the TLS 1.3 suites offered);
  (4) no complete hello: `handshake_timeout` if the connection lived to within 250 ms of `Tls:HandshakeTimeout`, else `client_closed`;
  (5) `other`. Reason text and details are built from enumerations only (version names, suite names, chain status flags); SNI and ALPN are filtered
  to hostname-like ASCII. No secret, certificate body or OS message ever enters an event.
- **Reliability per OS.** Because the classification reads what the client *offered*, it is identical on every OS. Verified on **Windows 11 (SChannel,
  .NET 10.0.14)** and in a **Linux container (OpenSSL, .NET 10.0.14)**: all reasons above, with real clients (`SslStream`, `HttpClient`, raw sockets). Not
  observable: the exact OS-level reason inside a hello that looked acceptable (that becomes `other`). A ClientHello split across several records
  (very large hellos) is `other`. A handshake that fails *after* an acceptable hello for a reason on the server side (for example an unusable
  server key) is `other` too. (Session resumption is not observed but disabled, see "M3: TLS stack"; `Resumed` is `false`.)
- **Events and the sink.** `ConnectionEvent` (flat record, no secrets by construction; a test pins that it has no certificate, byte-array or exception
  member). `IConnectionEventSink.Publish` never blocks and never throws into the connection path. `ConnectionEventSink` assigns increasing sequence
  numbers and enqueues into a `BoundedDropOldestQueue<T>` (a bounded `Channel` with `DropOldest`, default capacity 10 000, `Dropped` counter; reusable
  for the inspector in M4). `ConnectionEventPump` (hosted service) drains the sink into `ConnectionEventStore` (a bounded ring, default 2 000,
  `Snapshot()`, `WaitForAsync`); M4's inspector pipeline reads the same `Reader`. The connection path only ever enqueues.
- **Metric:** `ekmmock_tls_handshake_failures_total{reason}` is a `System.Diagnostics.Metrics` counter on `Meter("EkmMock")` (label values are the
  snake_case reasons) plus in-memory counts (`EkmMetrics.HandshakeFailureCounts`). The Prometheus exposition and the other instruments come with M7.
- **Per-request link:** `EkmExchangeMiddleware` finds the `ConnectionState` by `HttpContext.Connection.Id` and counts the request
  (`closed.RequestCount`; keep-alive reuse and HTTP/2 multiplexing are both visible).

## M3: Server certificate hot reload (spec 5.3)

- `ServerCertificateProvider`: PEM chain + PKCS#8/PKCS#1/SEC1 key from `Tls:CertFile` / `Tls:KeyFile` (leaf first, intermediates after; at most 8
  certificates). A `FileSystemWatcher` on the files' directories triggers a debounced reload (`Tls:Debounce`, default 500 ms; cert and key are usually
  written one after the other) and a **poll** (`Tls:PollInterval`, default 60 s) is the fallback for volume mounts and symlink swaps that raise no
  events (tested with the event path parked for an hour and a 300 ms poll). The poll compares a SHA-256 over both file contents, so an unchanged
  file is parsed once, and an unusable file is judged **once per content** (no repeated warning every poll).
- **Atomic swap:** the candidate is loaded and validated off to the side (key belongs to the certificate, `serverAuth` EKU present or no EKU, not
  expired, key usable), then published with one volatile write. Handshakes in progress and existing connections are untouched (a keep-alive
  connection keeps the old certificate until it closes); new connections get the new one. Tested: six concurrent workers (four long-lived
  keep-alive connections, two that open a new connection per request) issue requests continuously while the files are replaced: **zero failed
  requests**, requests keep flowing after the swap, and the served thumbprint changes within the 200 ms test poll.
- **Invalid or partial replacements keep the old certificate:** garbage, a new certificate with the old key (mismatch), a client certificate
  (no `serverAuth`), an expired certificate: each logs one warning, sets `LastError`, and serves the old certificate; fixing the files recovers
  and clears the error. An expired certificate **at startup** is still loaded (flagged `IsExpired`, logged at error level) so the operator gets a
  running console that shows the problem. A missing/unreadable/broken certificate at startup refuses to start with a clear message.
- **Replaced certificates are disposed after a grace period** (`Tls:RetiredCertificateGrace`, default 2 min) because a handshake that started
  before the swap may still use them (relevant for Windows key containers).
- **Console seam:** `IServerCertificateProvider.ReplaceAsync(certPem, keyPem)` validates, writes key then certificate atomically (temp file + rename,
  `0600` for the key on Unix) when files are configured, swaps, and clears `LastError`; invalid input throws `ServerCertificateException` and changes
  nothing. `Info` (`ServerCertificateInfo`) exposes subject, issuer, **SAN list**, not-before/after, SHA-256 thumbprint, chain length, source
  (`File`/`Uploaded`/`DevelopmentGenerated`), loaded-at, **`ExpiresSoon` (within `Tls:ExpiryWarningDays`, default 30)**, `IsExpired`,
  `IsDevelopmentCertificate`. Expiry is also logged as a warning/error at load.
- **Dev convenience:** with `--dev` and no `Tls:CertFile`, a throw-away root CA (random-suffixed name) and a 60-day `localhost`/`127.0.0.1`/`::1`
  server certificate are generated in memory (`Source = DevelopmentGenerated`, `IsDevelopmentCertificate = true`, warning "DEV MODE" at startup,
  `DevelopmentRootCaPem` for the console). Without `--dev` and without files the host refuses to start. Configured files always win over dev mode.
  M8's `ekmmock certs` / the dev script produce persistent test PKI with the same library.
- **Server certificate versus Learn:** Learn says the proxy presents a certificate that chains to the root CA registered on the connection and
  whose SAN matches the host (or `server_subject_common_name` for Private Link). EkmMock serves leaf + intermediates, never the root, and shows
  the SAN list; the SAN/FQDN match itself is the operator's choice of certificate (the console warning for a mismatch with `Tls:ServerName` is an
  M6 item).

## M3: Learn comparison ("Configure networking and mTLS", read 9 November 2026)

Agreement: TLS 1.3 minimum (EkmMock: TLS 1.3 only, which is the highest version .NET offers); required cipher suites exactly
`TLS_AES_256_GCM_SHA384` and `TLS_AES_128_GCM_SHA256`; the proxy listens on TCP 443 (port 443 is required; EkmMock listens on 8443 by default and
the container maps 443 to it, open question 6 stands for the non-root bind); `--server-ca-certificate` is the **root** CA (EkmMock serves leaf +
intermediates and never relies on the root being sent); the server certificate must chain to it, be within its validity window and have a SAN that
matches the host; the client certificate is allow-listed by **subject common name and root CA, never by fingerprint**, which survives Microsoft's
rotation; IP allow-listing is not supported and mTLS is the only access control (no IP filter exists in EkmMock); certificate rotation of the
Managed HSM client certificate needs no action while CN and `caCertificates` are unchanged.

One tension, recorded as open question 17 instead of being decided silently: Learn's note says an attacker without a valid Managed HSM client
certificate "can't complete the handshake". Spec 5.1 requires `ClientCertificateMode.AllowCertificate` so that a request *without* a certificate
receives the JSON `401`. EkmMock follows the spec: a certificate that does not chain to a trusted CA fails the handshake; **no certificate** completes
the handshake and gets `401 Unauthenticated` for every operation (no operation is ever served without an authorized certificate).

## M3: Not covered / deliberately skipped

- **The 60 s default poll and the 120 s keep-alive timeout are not waited for**: the poll interval is configurable and tested at 200-300 ms, the
  default values are asserted (`TlsOptions`, `KestrelServerOptions`).
- **TLS session resumption** is disabled rather than observed (`Resumed` is reported as `false`); see "M3: TLS stack".
- **HTTP/2 specifics:** negotiated and authorized correctly on the real listener, but what Managed HSM actually uses is unknown (open question 5).
- **Cipher enforcement is verified on Linux only in a container**, on a Windows-built binary (see the report in the commit message and the next
  bullet); there is no CI run yet (M9).
- **Linux test path:** `tests/run-server-tests-linux.ps1` builds on the host and runs the server tests in `mcr.microsoft.com/dotnet/sdk:10.0`
  (Docker Desktop, Linux containers). The container could not restore NuGet packages in the environment where M3 was built (TLS handshake failure
  towards api.nuget.org from inside the container), so the script runs the **already built** portable output on the container's runtime
  (.NET 10.0.14, OpenSSL). It needs a stub content root for `WebApplicationFactory` (Windows path baked in at build time), which the script creates.

## M4: Where the code lives

- `src/EkmMock.Server/Inspector/` (everything `internal`, still only `Program` is public): `ExchangeCapture.cs` (middleware, per-exchange session, record factory),
  `CaptureStreams.cs` (the two stream wrappers and the pooled 16 KiB buffer), `SecretMasking.cs` (secrecy rule, fingerprint, redactor, retained secrets),
  `ExchangeRecord.cs` (the record and its groups, the connection event DTO, JSON context), `InspectorPipeline.cs` (bounded queue, consumer, stage interface),
  `ExchangeRingBuffer.cs` (ring buffer, filters, paging), `InspectorFeed.cs` (live feed), `InspectorJsonlWriter.cs`, `AuditLog.cs`, `DashboardAggregator.cs`,
  `InspectorService.cs` (the console-facing contracts `IInspectorQuery`/`IInspector`, reveal, replay seam, export, connection statistics), `KqlSnippets.cs`,
  `InspectorOptions.cs` (`Inspector`, `Limits` options, budget status, reveal gate).
- Small hooks in M2/M3 code: `EkmRequestContext` got `AuthElapsed`, `InjectedDelay`, `QueueWait`, `FaultRule` (the last three are filled by M7), `EngineCalled`,
  `RequestNumberOnConnection`; `EkmAuthMiddleware` times the authorizer; the three handlers set `EngineCalled`; `ConnectionState.RequestStarted` returns the ordinal;
  `BoundedDropOldestQueue` takes an optional `onDropped` callback; `ConnectionEventPump` also hands every event to the inspector stages. Nothing else changed in the
  EKM path: all M2/M3 tests pass unchanged (the one edit to an existing test is a new allowed log field, see "Logging" below, and a de-flaked log helper, see "Tests").

## M4: Capture pipeline (spec 8.1, 8.3)

- **Position:** `InspectorCaptureMiddleware` is the first middleware of the EKM branch (`Capture → Exchange → Route → [Faults] → Auth → [Limits] → Dispatcher`), so it sees every
  exchange on an EKM port: 2xx, 400 variants, 401, 404 (also unroutable paths), 405, 5xx, oversize bodies. A test pins the order in `EkmPipeline.cs`.
- **Deviation from the spec text (recorded on purpose): no `EnableBuffering`.** Spec 8.3 says "buffers the request body (`EnableBuffering`, max 16 KiB)". `EnableBuffering` makes the
  *capture* read the whole body before routing and authentication, which would change what M2/M3 do (a client that sends headers and no body would hold up a 401/404; Kestrel's body-size
  exception, which M2 maps to `400 InvalidRequest`, would be thrown inside the capture instead of the dispatcher; chunked bodies would be buffered twice). Instead `Request.Body` is wrapped by a
  pass-through stream that copies what the pipeline reads (at most 16 KiB, the rest is counted) and `Response.Body` by one that copies what is written (at most 16 KiB). Reads and writes,
  including exceptions, reach the real streams unchanged; nothing is buffered, delayed or reordered. The stream wrappers are restored when the exchange ends.
- **A request that is rejected before its body is read** (`401`, `404`, `405`, bad `api-version`/key name/content type): after the response has been written the capture reads at most 16 KiB of the
  rest through the same wrapper (`DrainTimeout` 100 ms, any failure just ends the capture of the body), so that rejected requests are captured with their body. The client already has its
  answer (Kestrel flushes the response on write); the only effect is that the keep-alive connection is held for at most 100 ms longer when a client sent fewer bytes than it declared (tested over a raw TLS socket:
  answer in well under 1 s, body captured afterwards). This wait is outside the overhead measurement because it is I/O, not capture work.
- **Size and truncation:** `SizeBytes` is the larger of the observed bytes and the declared `Content-Length`; `Truncated` means more than 16 KiB passed; the text covers the first 16 KiB.
- **The record** (`ExchangeRecord`, groups of spec 8.1) is built *after* the exchange from `EkmRequestContext` (exchange id, connection id, route, ids, alg, error code, timings), the
  `ConnectionState` of M3 (TLS protocol, cipher, ALPN, SNI, handshake time on the first exchange of a connection only, request ordinal; `Resumed` is `false` because resumption is disabled) and
  the `EkmAuthResult` of M3 (certificate, chain result, CN allowed, namespace matched, internal failure reason). `ReceivedAtUtc` is truncated to microseconds. Requests rejected before Auth (an unroutable
  path) still show the certificate of the connection and `AuthEvaluated=false`. Key facts (`oct`/`RSA`, size, state, wrap/unwrap counters *after* the call) are read with `IKeyManager.Get`
  only when a handler asked the engine about the key and the answer was not `404` (so no tombstone lookup under the store lock). `request_id`/`correlation_id`/`pool_name` come from the dispatcher or, for
  requests it never parsed, from the captured body, so a rejected request can still be found by `correlation_id`. Headers: at most 64, values at most 1024 characters, `Authorization`/`Cookie`/... are `[redacted]`.
  Fields for M7 exist now and are zero/null: `InjectedDelayMs`, `QueueWaitMs`, `Faults.Rule`.
- **Never awaits the consumer:** the request path only calls `InspectorPipeline.Enqueue`, a non-blocking write into a bounded `Channel` (default capacity 8192, `Inspector:ChannelCapacity`) with
  `DropOldest`. Every drop increments an in-memory counter and the `ekmmock_inspector_dropped_total` instrument on `Meter("EkmMock")` (connection events dropped by their own queue count there too) and zeroes the raw
  secrets of the dropped record. Proven with a deliberately blocked consumer: 100 requests while it is stuck all complete, the median latency does not move, exactly `100 − capacity` captures are dropped, and the buffer
  ends with the newest records.
- **Capture never fails a request:** everything the capture does on the request thread is inside try/catch (the body-seal inside a read as well); a failure is counted (`CaptureDiagnostics.Failures`) and logged
  once per 1000 with the exception *type* only (a parser message can quote the request). A stage failing on the consumer side is isolated from the other stages (`InspectorConsumer.StageFailures`).
- **Consumer and stages:** one `BackgroundService` reads the queue and calls the stages in order: ring buffer, dashboard aggregator, connection statistics, live feed, JSONL writer (so a record is queryable before a
  console is told about it). `OnIdle` (queue empty) flushes the JSONL file. At shutdown the consumer drains what is left and completes every feed subscription. Connection events keep their own queue
  and pump (M3); the pump now also hands each event to the stages.
- **Logging:** the log line gets `injected_delay_ms` (zero until M7); the existing test that pins the field set was extended by that one name. **The 150/250 ms warning/error levels of spec 9 are not
  in M4**: the data exists, but the M2 test pins level `Information` for every line and a first request on a loaded machine can legitimately take more than 150 ms (JIT), so the thresholds would make that test
  and others flaky; M7 owns fault delays and rewrites those tests anyway. `Limits:LatencyBudgetMs` (250) and `Limits:LatencyWarningMs` (150) exist now and drive the budget colour.
- **Budget status** (`LatencyBudget.Classify`, pure): green below 150 ms, amber from 150 ms up to and including 250 ms, red above 250 ms (boundaries tested at 149 / 150 / 250 / 251 ms). "Over budget" in the filter and
  the dashboard means red.

## M4: Secret handling in the inspector (spec 8.4)

- **The rule per (operation, direction)** (`BodyPositions.For`):

  | Body | Position | Treatment |
  |---|---|---|
  | `wrapkey` request | `SecretRequest` | `value` is the plaintext DEK: masked |
  | `unwrapkey` response | `SecretResponse` | `value` is the plaintext DEK: masked |
  | `unwrapkey` request | `CiphertextRequest` | ciphertext: shown as sent; a body that is not one complete JSON object is not captured |
  | `wrapkey` response | `Plain` | ciphertext: shown as sent |
  | `info` / `metadata` request | `NoDekRequest` | shown as is, except a stray `value` (should not be there) is masked; not-JSON is shown (that is what one wants to see) |
  | every other response (ProxyErrors, `info`, `metadata` with `n`/`e`) | `Plain` | shown as is |
  | an **unroutable** request (operation unknown) | `SecretRequest` | a DEK may have been sent to a wrong path: treated like a wrap request. Its response is a plain ProxyError |

- **Masked form and fingerprint:** `32 bytes · fp 3f9a1c07b2e4` = decoded length and the first 12 hex characters of the SHA-256 of the raw (decoded) bytes. Padded and unpadded base64url of the same bytes give the same
  fingerprint (decoding uses the same strict `Base64UrlCodec` as the endpoint), and the same DEK gives the same fingerprint in the wrap request and the unwrap response (tested end to end).
- **How a body is masked:** on a secret position the masked text is *built from the parsed JSON* (a `Utf8JsonReader` pass over the bytes that replaces value tokens by their masked form and copies the rest);
  the original bytes are never turned into a string, and the buffer is zeroed as soon as the request body ends (the wrapper tells the session at end of stream, so for a wrap request the raw copy lives for a
  few microseconds after the dispatcher has read it, not until the end of the exchange). Rules on a secret position: any property named `value` (case-insensitive, at any depth) is masked (`value` strings by
  length+fingerprint; a string that is not valid base64url as `value (invalid, N chars)` with **no** fingerprint; a non-string as `value (invalid, not a string)`); at the top level only an allow-list is shown
  (`request_context`; `alg` only when it is exactly one of the four algorithm names, compared as bytes so that a DEK in the `alg` field never becomes a string; on a response `code` and `message`), every other
  top-level property is replaced by `(masked, N chars)`. That covers a DEK under a wrong field name or case, in `alg`, or in `request_context.value`.
- **Unparseable-body policy (conservative):** a body on a secret position (and an unwrap request) that is not exactly one complete JSON object (bad JSON, trailing content, bad UTF-8, a scalar or array root, nesting
  deeper than 32, larger than 16 KiB) is **not captured**: `Captured=false`, only the size and the note "Unparseable body not captured" are stored. `request_context` ids are still read from such a body when it
  starts with a readable object, so it stays searchable by `correlation_id`. An oversize unwrap response (an A256KW DEK above roughly 12 KB would not fit in 16 KiB of base64url) is likewise not captured.
- **Headers carry no DEK** (the DEK is only in bodies); sensitive header names are redacted anyway. Logs, JSONL files, exports, the live feed, the dashboard and the audit log are all built from `ExchangeRecord`
  or fixed fields; a structural test walks the record types and fails if one could hold a `byte[]` or the retained secrets.
- **Fingerprint caveat:** a 48-bit fingerprint of a *low-entropy* value could be brute-forced; real DEKs from Azure are random 256-bit keys. It is what the spec asks for; noted in OPEN-QUESTIONS.
- **Limits of managed memory** (README in M9): the JSON reader and the HTTP stack may copy bytes the runtime owns; buffers EkmMock owns are zeroed, strings cannot be. `Reveal` necessarily produces a string.

## M4: Reveal, retention and audit (spec 8.4, 5.4)

- **Gate:** reveal is possible only when `Inspector:SecretDisplay=Reveal` **and** the process was started with `EKMMOCK_INSPECTOR_ALLOW_REVEAL=true` (read once at construction of `EnvironmentRevealGate`,
  never from configuration; `InspectorOptions` has no member that could grant it). `Reveal` without the environment flag, or the flag without the setting, is `Masked`: nothing raw is retained.
- **Retention (only when allowed):** `RetainedSecrets` holds the complete raw request body of an exchange (for reveal of a wrap DEK and for replay) and the complete raw response body of an unwrap (for reveal of the
  unwrapped DEK), as `byte[]`. It is **not part of the record**: it lives in the ring buffer slot of its exchange (the record type has no place for it), so the JSONL writer, the export, the feed and the dashboard
  cannot reach it. It is zeroed when the slot is evicted, when the buffer is cleared, when the capture queue drops the record, and when the capture fails. A body above 16 KiB is never retained.
- **`IInspector.Reveal(exchangeId, field, user)`** (`request.value` / `response.value`): refuses when the gate is closed (`InspectorRevealException(Disabled)`, and the *denied attempt* is audited as
  `inspector.reveal.denied`), reads the value under the ring buffer's lock (an eviction cannot zero it mid-read), **writes the audit entry first and returns the value only if that succeeded** (fail closed:
  `AuditUnavailable`). Other failures: `UnknownField`, `ExchangeNotFound`, `NotRetained`.
- **`IAuditLog`** (`FileAuditLog`, `audit.jsonl` on the data volume): append-only JSONL `{at, user, action, target, detail}`, one `Write` of one line under a lock, flushed to disk before `Append` returns, fields bounded
  to 256 characters and JSON-escaped (a hostile user name cannot forge a line). The reveal entries are `inspector.reveal` with target `exchange:<id>/<field>` (never the value). M5 provides the user identity, M6 the Audit page
  and the other state-changing actions.
- **Replay seam:** `IInspector.CanReplay(id)` is true iff the gate is open, the exchange is in the buffer and its raw request body was retained (so not for an oversize body); otherwise the reason is
  `RevealNotAllowed`, `ExchangeNotFound` or `BodyNotRetained`. `ReplayAsync` checks that, audits (`inspector.replay`) and hands a private copy of the body to the registered `IReplaySender` (M6 implements it with
  the console test client certificate; the sender disposes the request, which zeroes the body). Without a sender it says so and sends nothing.

## M4: Ring buffer, filters, feed (spec 8.3, 8.5)

- **Ring buffer** (`Inspector:RingBufferSize`, default 10 000): a circular array behind one short lock, kept sorted by exchange id (records arrive in completion order, which differs slightly from start order under
  concurrency; late arrivals are bubbled back a few places), so lookup is a binary search and newest-first is the tail. Readers copy references out and filter outside the lock. Memory: a typical record is a few KB
  (small bodies). **Superseded by the security review follow-up:** the buffer is now also bounded in estimated bytes (`Inspector:MaxBytes`, default 128 MiB) and what an unauthenticated peer can make a record hold is capped (headers 4 KiB, bodies 1 KiB each); the original note only counted bodies (two 16 KiB bodies per record as UTF-16 text) and missed up to 64 headers of 1024 characters per side, so a flood of anonymous requests with large headers could take about 100 KB per record, roughly 1 GB at 10 000 records. See [Security review follow-up](#security-review-follow-up). A dashboard
  snapshot sorts the retained latency samples (at most 4096 per operation and minute), which is milliseconds, not microseconds: poll it every few seconds, not per request.
- **Filters** (`ExchangeFilter`, combined with AND): `Operation`, `Namespace`, `Key`, `ClientCommonName` are exact and case-sensitive (a CN is case-sensitive everywhere); `Text` is a case-insensitive substring of
  `correlation_id`, `pool_name`, `request_id`; `StatusClass` 2/4/5; `OnlyErrors` = status ≥ 400; `OnlyOverBudget` = red; `HideInfo` hides the health probes.
- **Paging:** newest first, `Limit` clamped to 1..1000; `BeforeId` continues with older records (`NextBeforeId` is the cursor, `HasMore` says whether there are more), `AfterId` returns what is newer than a cursor
  (catch-up after a pause). Ids are sequential, so cursors stay valid while the buffer evicts.
- **Live feed** (`IInspectorFeed.Subscribe`): every subscriber has its **own** bounded `DropOldest` channel (`Inspector:SubscriberCapacity`, default 1000) with its own `Dropped` counter; publishing never blocks, a
  subscriber that never reads loses only its own oldest items, `Dispose` unsubscribes and completes the reader, host shutdown completes everyone. Optional per-subscriber filter and the "connection events inline"
  toggle. Items are immutable and shared between subscribers.
- **Connections** (spec 8.2/8.5): `ConnectionEvents` (newest first, filter by kind/connection/failures), `OpenConnections` (from the M3 registry: remote endpoint, age, request count, TLS facts, client
  certificate subject), `ConnectionStatistics` (opened, handshakes succeeded/failed with a count per reason, closed, resumed handshakes, **resumption rate** — always 0 here because resumption is disabled —, requests on
  closed connections and the average per closed connection). Connection events are also JSONL lines (`"type":"connection"`) and feed items.

## M4: JSONL files (spec 8.3)

- `Inspector:Persist=true` writes to `<Data:Path>/inspector` (or `Inspector:PersistPath`): `inspector-yyyyMMdd.jsonl` (UTC day, **daily rotation**; the clock is the injected `TimeProvider`), rolled over to
  `inspector-yyyyMMdd.1.jsonl`, `.2`, ... before a file would exceed `Inspector:MaxFileBytes` (default 50 MiB, **size cap**; a single line larger than the cap gets a file of its own). Whenever a file is opened, files
  older than `Inspector:RetainDays` (14) and then the oldest files beyond `Inspector:MaxTotalBytes` (500 MiB) are deleted (**prune**); the file being written and files that are not the inspector's are never
  touched. After a restart the day's last file is continued while it has room.
- One JSON object per line, `snake_case`, `"type":"exchange"` or `"type":"connection"`, written with the same source-generated serializer as the export, flushed when the queue runs empty (connection events at once).
  The `·` of the masked form is written as `\u00B7` (the serializer's default escaping; the parsed text is identical). **Always masked**: the writer only ever sees `ExchangeRecord`, and no code path hands it raw
  bytes. Writes are serialised by a lock (two consumer threads); an I/O error drops that line, closes the file and logs (rate limited), it never reaches a request.

## M4: Dashboard aggregates and contracts (spec 8.5)

- `DashboardAggregator` is a stage (consumer side, never the request path) with per-minute buckets covering the last hour regardless of the ring buffer size: per minute and operation the count, errors by code,
  over-budget count, maximum, and up to `Inspector:MaxSamplesPerMinuteAndOperation` (4096) latency samples (reservoir sampling beyond that, so memory is bounded and counts stay exact).
  Percentile method: **nearest rank**, `sorted[ceil(p/100·n) − 1]` (an observed value; the p95 of 1..100 ms is 95 ms). Windows (15 min and 1 h) cover the current minute and the N−1 before it. Snapshot: per-operation
  count/p50/p95/p99/max/errors/over budget and the share over budget, errors by code (`HTTP <status>` when there is no code), requests per minute by operation and p50/p95/p99 per operation per minute for the last 60
  minutes, the Managed HSM heartbeat (last `info`: time, client CN, status, age, `IsStale` when older than 60 s or never seen; the last *successful* `info` separately, because a rejected probe still proves that Managed HSM
  reaches the endpoint), the dropped-capture counter and the number of exchanges since start. An unroutable request counts as `(unrouted)`.
- Contracts for M5 and the CLI: `IInspectorQuery` (`Query`, `Get`, `Count`, `ConnectionEvents`, `OpenConnections`, `ConnectionStatistics`, `Dashboard`, `Status`, `Kql`) and `IInspector` (adds `Feed`,
  `Reveal`, `CanReplay`, `ReplayAsync`, `ExportAsync`). `Status` reports ring capacity/count/evictions, drops, queue capacity, captures, capture failures, persistence, secret display mode, whether reveal is allowed and the
  number of feed subscribers. Export (`ExportFormat.Json`: `{exported_at_utc, masked:true, count, exchanges:[…]}`; `Jsonl`: one exchange per line, the file shape) is built from `ExchangeRecord` only, oldest first,
  with the same filter. HAR is not provided.

## M4: KQL snippet (spec 8.5)

- Pure function `KqlSnippets` (`ByCorrelationId`, `ByKeyAndTime`, `For(record)`), schema from Microsoft Learn ("Logging and monitoring for Managed HSM external key management" and "Troubleshoot Managed HSM external
  key management", read 9 November 2026): table `AzureDiagnostics`, `ResourceProvider == "MICROSOFT.KEYVAULT"`, `OperationName` `EkmGetProxyInfo` / `EkmGetKeyMetadata` / `EkmWrapKey` / `EkmUnwrapKey`, key identifier inside
  `requestUri_s`, `ResultType`, `ResultDescription`, `TimeGenerated`. Learn does **not** say which column carries the proxy `correlation_id` (`correlationId_g` in one article, `CorrelationId` in another), so the
  primary query matches either with `column_ifexists(...)` (a missing column is not an error) and a second query implements the documented fallback (key identifier + ±1 s window). Client text is escaped
  into the KQL string literal; control characters are dropped. See OPEN-QUESTIONS.

## M4: Overhead benchmark (spec 8.3, 14 test 24)

- **Method** (`InspectorOverheadBenchmarkTests`, `[Trait("Category","Benchmark")]`, runs with the normal test run but alone: `DisableParallelization` collection). The real EKM pipeline (Exchange, Route, Auth, Dispatcher, the
  real software HSM, real AES key wrap) runs on `DefaultHttpContext` objects with in-memory bodies, with and without the capture middleware in front, the real consumer thread running; 10 000 warm-up requests, then
  20 000 measured, mix of wrap, unwrap, info, metadata (AES-256, A256KWP, 32-byte DEKs; RSA left out, its millisecond-scale crypto is noise for a capture comparison), once in default masked mode and once with reveal
  allowed (extra raw copies). Two numbers: (1) **capture overhead**: `Stopwatch` timestamps inside the middleware around exactly its own work (stream wrapping, body copies, masking, record building, enqueue, buffer
  release; not the pipeline's time, not the rejected-request body wait), asserted `p99 < 1 ms`; (2) an **end-to-end A/B** of the same requests through both pipelines, interleaved A-B / B-A, asserted `p99(with) − p99(without) < 1 ms`
  and `p50` difference `< 1 ms`. It also asserts that no capture was dropped. The 1 ms threshold is not relaxed.
- **Measured** (Windows 11, .NET 10.0.14, 8 logical cores, Debug build of the test assembly, final full test run; microseconds per request, 20 000 requests each):

  | Run | Capture overhead p50 / p90 / **p99** / max | Pipeline with capture p50 / p99 | Pipeline without capture p50 / p99 | End-to-end difference p50 / p99 | Dropped |
  |---|---|---|---|---|---|
  | Masked (default) | 45.0 / 55.0 / **125.9** / 12 518 | 62.1 / 235.3 | 21.2 / 119.8 | +40.9 / +115.5 | 0 |
  | Reveal allowed | 49.4 / 62.1 / **134.4** / 14 151 | 75.2 / 229.2 | 26.8 / 114.9 | +48.4 / +114.3 | 0 |

  So the capture adds roughly 45 µs at the median and about 0.13 ms at p99, about one eighth of the 1 ms budget. Earlier runs during development gave p99 between 95 and 135 µs. The same test also passes in the
  Linux container (`tests/run-server-tests-linux.ps1`). Numbers are appended to `inspector-benchmark.txt` next to the test assembly on every run.
- **Outliers:** the maximum (10 to 20 ms) is a single-sample event that also occurs *without* the capture (GC or tiering on a loaded dev machine); it is reported, not asserted; p99 is what the spec asks for.

## M4: Tests

- New test classes (all in `tests/EkmMock.Server.Tests`): `SecretMaskingTests` (secrecy rule, fingerprint, every masking case, structural no-leak), `ExchangeRingBufferTests` (capacity, eviction order, each filter,
  paging, secrets zeroed, parallel writers/readers), `DashboardAndBudgetTests` (budget boundaries, KQL, aggregates with known data), `FeedJsonlAndAuditTests` (feed, JSONL rotation/cap/prune/concurrency, audit),
  `InspectorCaptureTests` (every request kind captured on the in-process host, record groups, usage counters, within 1 s, full queue with a blocked consumer, eviction, status), `InspectorMaskingEndToEndTests`
  (masking end to end, rejected requests that carry a DEK, **the leak scan of spec 14 test 18 across ring buffer, JSONL files, exports, live feed, logs, dashboard/status and audit log**, export), `InspectorRevealTests` (gate,
  denied, allowed with audit, failures, fail-closed audit, eviction, replay seam), `InspectorMtlsTests` (real Kestrel mTLS: 401 without certificate and with a wrong CN or namespace, valid caller with TLS facts per
  connection, 404/405/400/503, chunked oversize body, a request that never sends its body, connection events incl. a handshake failure with reason, open connections, statistics, JSONL), `InspectorOverheadBenchmarkTests`.
- **The 429 case is a skipped placeholder** (`ATooManyRequestsExchange_IsCaptured_WhenLimitsExist`): nothing produces 429 before M7 (Limits). The capture itself is status-agnostic and is proven with every other status.
- **Existing tests:** none weakened. Two edits: `LoggingAndLeakTests.AllowedLogFields` gained `injected_delay_ms`, and `MtlsEndpointTests.LastExchangeLog` now waits (up to 10 s) for the log line instead of reading it at once.
  The log line is written by the Exchange middleware *after* the response has been flushed, so on a real listener a fast client could read the log before it existed; this showed up once under CPU load
  (`Sequence contains no matching element`, reproduced with 12 busy processes, then fixed). It was a race of the M3 test helper, not of the server.
- **Flakiness:** the server test project (708 tests, 5 skipped) was run six times in a row on the final code: 6 of 6 green, 27 to 31 s each. While building M4 two flakes surfaced and were fixed, both test-side: the M3 log helper race above, and my own
  blocked-consumer test (a queue of 8 can legitimately drop in a free phase on a loaded machine; it now drains before arming and asserts deltas). The new tests were also stressed under heavy CPU load (8 consecutive runs of
  the inspector classes with 12 busy processes: no failure). Random inputs in tests are constructed so that they cannot accidentally be valid (for example the "invalid base64url" value always contains `+` and `/`).

## M4: Not covered / deliberately skipped

- **Spec 9 log levels (warning above 150 ms, error above 250 ms)**: left for M7 (reason above). **Metrics exposure** (`/metrics`): M7; the `ekmmock_inspector_dropped_total` instrument exists on the meter.
- **Replay sending** (M6), **console pages and the Blazor hub** (M5), **`/api/console/*` and the CLI export** (M5/M8): only the service layer exists. HAR export is not provided (JSON and JSONL are).
- **Capture of request bodies larger than 16 KiB** is truncated by design; a *secret-position* oversize body is not captured at all (only its size).
- **No capture of the TLS handshake bytes**, only M3's connection events. `TLS session resumed` is always `false` (resumption is disabled, DECISIONS "M3: TLS stack").
- **Linux container result:** the full server test project ran in `mcr.microsoft.com/dotnet/sdk:10.0` via `tests/run-server-tests-linux.ps1` (OpenSSL): 708 tests, 0 failed, 1 skipped (the 429 placeholder); the four Linux-only
  cipher tests ran and passed there.

## M5: Console (Fluent UI Blazor, auth modes, endpoint separation)

### Packages
- **Fluent UI Blazor 4.14.5** (`Microsoft.FluentUI.AspNetCore.Components` + `.Icons`), not 5.0.1 (the latest stable). The repository skill documents v4 (`FluentSelect Items/OptionText/OptionValue`, `FluentDesignTheme`, providers); v5 renames and
  restructures parts of that API and there is no gain for this console. Revisit when the skill is updated. All assets come from the package's static web assets: no CDN, no font fetch, no manual `<script>`/`<link>` for the library.
- **Microsoft.Identity.Web 4.18.0** (OIDC sign-in), **bunit 2.13.3**, **Microsoft.Playwright 1.64.1**; all pinned in `Directory.Packages.props`.
- **`JsonSerializerIsReflectionEnabledByDefault=true`** (was false). Blazor Server serialises circuit/component data with reflection and failed at runtime otherwise. Everything *we* serialise still uses source-generated contexts;
  an architecture test (`own JSON is source generated`) scans the source so that stays true.
- **Razor components are public** (the Razor compiler always makes them so), so the M2/M3 architecture rule "no public types" now allows public types only in `WebConsole*` namespaces (components and their plain-data models, which
  component parameters need to be public). `Program` stays the only other public type. Identity.Web references `Microsoft.AspNetCore.Mvc.Core`, so the M2 "no Mvc.Core reference" test became a source scan for MVC/ProblemDetails use.
  Listener configuration is allowed in `EkmKestrel.cs` and `ConsoleKestrel.cs` (was `EkmKestrel.cs` only).
- Namespace is `EkmMock.Server.WebConsole` (a `Console` namespace clashes with `System.Console`); folder stays `Console/` as in spec 16.

### Endpoint separation
- Kestrel has two listeners: EKM (mTLS, 8443) and Console (`Endpoints:Console:Url`, default `https://127.0.0.1:8080`, TLS 1.2/1.3, **no client certificate**). `UseEkmPipeline` branches on
  `HttpContext.Connection.LocalPort`: EKM port gives the EKM pipeline, console port gives the console pipeline, any other port gives 404. No host filters. EKM routes on the console port and Blazor/`/_blazor`/`/_framework`/`/_content`/`/api/console/*`/
  `/healthz`/`/readyz` on the EKM port both return 404, proven on real Kestrel listeners (ephemeral ports, `ListenerRegistry` records the bound ports).
- Console and EKM must use different ports (validated). Console requests are never captured as EKM exchanges or connection events (test).
- **Console certificate:** `Console:Tls:CertFile/KeyFile` if set, otherwise the EKM server certificate provider (so `--dev` auto-generates the throw-away, flagged localhost certificate via `EkmMock.Pki`).
- `/healthz` (process alive) and `/readyz` (key store loaded, self-test passed, EKM listener up) are anonymous, on the console port only, and contain no sensitive information. `/metrics` is **not** implemented (M7).
- Unknown console paths return 404 for every method (a catch-all route with the lowest order; otherwise POSTs got 405 from the static-assets route).
- Static assets: `MapStaticAssets` is only mapped when the server assembly's own manifest exists (a test process looked for the *entry* assembly's manifest). The Windows-built manifests contain Windows paths, so
  `tests/run-server-tests-linux.ps1` removes them in the container copy.
- The implicit global `UseAuthentication/UseAuthorization` that `WebApplication` adds at the top of the pipeline would have challenged EKM requests and `/healthz` in EntraId mode; the app sets the
  `__AuthenticationMiddlewareSet`/`__AuthorizationMiddlewareSet` markers and the console branch adds its own.

### Auth modes
- `Console:Auth` = `LoopbackOnly` (default) or `EntraId`. One validator (`ConsoleConfigurationValidator`) is the single source of truth, used by the builder pre-flight, `ValidateOnStart` and the Kestrel setup. Failure prints a clear message to
  stderr and exits with **code 78** (EX_CONFIG).
- **LoopbackOnly** + any non-loopback bind (`0.0.0.0`, `::`, `*`, `+`, a public IP, a hostname that does not resolve *entirely* to loopback) is refused. `localhost`, `127.0.0.0/8`, `::1`, `::ffff:127.0.0.1` are accepted. The user is the fixed identity `loopback`.
- **Loopback runtime check (decision):** the startup check is mandatory and cannot be turned off. In addition `Console:EnforceLoopbackClient` (default **true**) rejects a non-loopback remote IP at request time. With the mandatory bind check
  this is defence in depth only, and cannot fire for a correctly configured host. A container that publishes `127.0.0.1:8080:8080` sees the bridge address as remote IP, but it also cannot satisfy the bind check (see OPEN-QUESTIONS 33), so
  that deployment must use `EntraId` or set `EnforceLoopbackClient=false` knowingly. In LoopbackOnly the Host header must also be a loopback name (or in `Console:AllowedHosts`) as a DNS-rebinding defence, and in both modes a cross-origin `Origin`
  is refused for `/_blazor` and for non-GET requests.
- **EntraId** (Microsoft.Identity.Web, cookie `__Host-ekmmock-console`): needs TenantId, ClientId, an `https` Instance and either `AllowedObjectIds` or `AllowedGroupId` (GUIDs). The **client secret only comes from `EKMMOCK_CONSOLE_CLIENT_SECRET` or
  `..._FILE`**; a `Console:EntraId:ClientSecret` in configuration is refused in every mode and the secret is never logged or shown. Missing config refuses to start.
- **Policy `EkmMock.Console`** is the fallback policy for everything (pages, SignalR hub, `/api/console/*`); `/healthz` and `/readyz` are `AllowAnonymous`. `ConsoleAccessPolicy` allows an `oid` in the list (case-insensitive) or a matching `groups`
  claim and checks `tid`. Anonymous gets a challenge (a 401 instead of a redirect for `/api` and `/_blazor`), any other identity 403. Group-claim overage is not handled (OPEN-QUESTIONS 34).
- `IConsoleUser` is the one abstraction for the current user. `AuditName` is `loopback` or `Name (oid)`, and the audited reveal uses it. The circuit's identity is fixed when it connects (no revalidation within a circuit).
- **Antiforgery:** Blazor forms use the built-in antiforgery. The only state-changing API is `POST /api/console/exchanges/{id}/reveal`, protected by an endpoint filter (header `X-CSRF-TOKEN`, token from `GET /api/console/antiforgery`) and audited.
  A Bearer/Entra token policy for the CLI is left to M8. Data Protection keys persist (unencrypted) to `<Data:Path>/dataprotection`, falling back to in-memory keys when the folder is not writable.

### Headers and errors
- CSP: `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self' wss://{host}; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'`.
  `'unsafe-inline'` is for styles only (Fluent web components set inline styles); there is no inline script. A real-browser test caught two violations that were then removed (an inline `onclick` on the reconnect button and the inline script of
  `<ImportMap/>`, which is no longer rendered); behaviour lives in `console.js`. The browser test fails on any console error, CSP violation or failed request.
- Also `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, COOP/CORP, `Permissions-Policy`, `Cache-Control: no-store` (unless already set). HSTS only for non-loopback hosts (it applies to the host, not the port,
  so sending it on `localhost:8080` would affect other local sites).
- Non-development: a generic 500 without a stack trace; `CircuitOptions.DetailedErrors` only in Development; `ErrorBoundary` per page; the default Blazor reconnect UI with a minimal style.

### API
- `/api/console/*` uses **snake_case** (consistent with the EKM and inspector JSON) and **source-generated** `System.Text.Json`. Endpoints: `status`, `inspector/status`, `antiforgery`, `exchanges` (filters and paging), `exchanges/{id}`,
  `exchanges/{id}/kql`, `POST exchanges/{id}/reveal`, `connections`, `connections/open`, `connections/statistics`, `dashboard`, `export`. They are thin over `IInspector`/`IInspectorQuery`.
- `InspectorService.ExportAsync` was fixed to use only asynchronous writes (Kestrel disallows synchronous IO; found by the export endpoint test).

### Live traffic, feed batching and the 1 s guarantee
- One feed subscription per component (per circuit), disposed with it; no prerender (`InteractiveServerRenderMode(prerender: false)`) so a subscription is never created twice.
- A pump drains everything available, renders once, then waits `LiveTraffic:RenderIntervalMs` (default 150 ms, validated 20 to 900 ms so the worst case stays below 1 s) via `Task.Delay(.., TimeProvider)`. A 1000 req/s flood causes about 7 renders per
  second, not 1000. Measured exchange-to-visible latency: bUnit with a real mTLS request n=20 p50 153 ms, max 172 ms; real Chromium against the real server process p50 about 200 ms, max 225 ms (limit 1 s).
- The in-UI list is capped at `MaxRows` = 2000 (oldest dropped). **Pause** buffers new exchanges, shows the pending count and keeps at most `MaxPending` = 5000 (oldest dropped, and the drop is counted and shown). **Clear view** is view-only (remembers the last
  cleared id/time; the inspector keeps its data). A filter change reloads from the ring buffer; while paused it reloads a frozen view (`BeforeId`).
- The table is a `Virtualize` over a `role=table` div, not `FluentDataGrid` (variable-height inline connection rows and the batching are simpler and cheaper this way). `FluentDataGrid` is used for the open-connections table.

### Pages and components
- Live traffic (`/`), Exchange detail (side panel and deep link `/exchange/{id}`; tabs Overview, TLS & client certificate, Request, Response, Timing as SVG waterfall vs the 250 ms line; KQL snippet), Connections, Dashboard (window 15 min / 1 h, 2 s refresh by timer;
  heartbeat card ticks once per second from a `TimeProvider` timer without re-querying, red above 60 s with text and icon).
- **Tabs** are a small custom accessible component (arrow/Home/End keys, `role=tab`) instead of `FluentTabs`, to keep the keyboard behaviour and test hooks under our control.
- **Charts** are Razor/SVG components with plain-data models and no chart library: `LineChart` (percentiles with the 250 ms budget line), `StackedColumnChart` (requests per minute by op, integer count axis), `HorizontalBarChart` (errors by code), `Sparkline`.
  Razor reserves `<text>`, so a small `SvgText` component renders SVG labels.
- **Secrets:** masked display is `32 bytes · fp 3f9a1c07b2e4`. A bUnit leak scan (hex, base64, base64url of the raw DEK) proves masked mode never puts the value in markup. **Reveal** is shown only when allowed (`EKMMOCK_INSPECTOR_ALLOW_REVEAL` and
  `SecretDisplay=Reveal`), calls the audited service as the current user, keeps the value in component memory only (never JS, URL, storage, logs, export), and hides it after 30 s or on navigation.
- **Replay** is shown, enabled only for `CanReplay`, and prints "Replay is implemented in M6." It never calls the replay seam. The "faults active" banner is wired to `IFaultStatus` (always false until M7).
- Nav: Live traffic, Connections, Dashboard, plus disabled placeholders (Keys, Namespaces & trust, Certificates, Playground, Fault injection, Audit log, About) labelled with their milestone. Theme toggle (system/light/dark) via `FluentDesignTheme`, set after render.

### M5: Tests and results
- `tests/EkmMock.Console.Tests` (new: bUnit component tests, the live-update tests, and 6 real-browser tests with `Trait("Category","Browser")`; exclude with `--filter "Category!=Browser"`); host-level tests added to `EkmMock.Server.Tests`
  (`ConsolePortSeparationTests` for spec 14 test 16, `ConsoleStartupValidationTests` for test 17 incl. real child-process exit codes, `ConsoleAuthAndApiTests`).
- Playwright installs Chromium on demand; if no browser or server can start, the browser tests skip with an explicit reason (not triggered here: all 6 ran).
- Results on Windows: 1302 tests (Crypto 308, Server 831, Console 163), 1297 passed, 0 failed, 5 skipped (all in Server.Tests: the 429 placeholder and the four Linux-only cipher tests). Server and Console projects were each run 5 times in a row: 10 of 10 green.
  On Linux (container script) the Server project ran 831 tests twice: 0 failed, 1 skipped (the 429 placeholder), so the four cipher tests ran. A flake in `ConsoleRequests_AreNeverCapturedAsEkmTraffic...` appeared once on Linux (baseline taken
  while an earlier test's asynchronous capture was still draining) and was fixed test-side with a settle delay.

### M5: Not covered
- **Entra OIDC against a real tenant** was not exercised (policy, challenge, 403 and startup validation are tested with a fake scheme).
- Keys, Namespaces & trust, Certificates, Playground, Fault injection, Audit log, About pages (M6/M7), replay sending (M6), `/metrics` (M7), CLI (M8), packaging (M9).
- A visual pass with the editor's integrated browser tool was not done; the visual check used Playwright Chromium against the real server process (see the report).

## M6: Keys, namespaces and trust, certificates, playground, audit log, about

### Banners and contrast (fix found in the M5 visual review)
- In the light theme the DEV MODE banner text was washed out. `FluentMessageBar` colours its text with the status colour, which fails WCAG AA on the pale tint. Replaced with our own `ConsoleAlert` component: tinted background, the normal
  foreground token for the text, the status colour only on the border and icon (`DevModeBanner`, `FaultsBanner` and all page alerts use it). I then measured every status class (chips, badges, alerts, budget colours) in both themes in the
  real browser and darkened `--ekm-warning` and `--ekm-error` (mix with the foreground) until all are at least 4.5:1. No hard-coded colours: Fluent design tokens only.

### Shared service layer, one code path for UI and API
- `Console/Admin/*`: `KeyAdminService`, `NamespaceAdminService`, `CertificateAdminService`, `PlaygroundService`, `AboutService` (behind `IAboutService`), `AuditRecorder`. The Blazor pages and `/api/console/*` call the same services (no HTTP self-calls), so
  validation, error text and the audit entry are identical. Failures are `ConsoleActionException(ErrorCode, message)` with messages written for people (never engine internals); the API maps codes to 400/404/409/422.
- **Audit action taxonomy** (`AuditActions.All`; one entry per state-changing action: user, UTC time, action, target, and a small `details` bag without secrets): `key.create`, `key.import`, `key.enable`, `key.disable`, `key.expiry.set`,
  `key.expiry.clear`, `key.destroy`, `namespace.create`, `namespace.update`, `namespace.delete`, `namespace.trust.import`, `namespace.trust.test-client`, `certificate.upload`, `certificate.generate`, `playground.wrap`, `playground.unwrap`,
  `playground.reveal`, `playground.reveal.denied`, `inspector.reveal`, `inspector.reveal.denied`, `inspector.replay`. An enumerating test walks every action through the API/services and asserts exactly one entry with the right user/action/target, and a
  second one asserts that no entry contains the secrets used in the scenario. Reveals are audited *before* the value is returned (a failed audit write refuses the reveal). The audit page and API are read-only; there is no edit or delete.

### Keys
- Create validates the name `^[A-Za-z0-9-]{1,64}$` and the type (AES-256, RSA 2048/3072/4096); engine errors are translated, not shown raw. Enable/disable, set/clear expiry (UTC, `yyyy-MM-dd HH:mm`).
- **Destroy is irreversible (crypto-shred) and needs the key name typed as confirmation, enforced server-side** (`ConfirmationMismatch`, 400, in the service, so the API cannot skip it). The tombstone stays listed as "Destroyed". A destroyed name is reserved:
  creating a key with that name is refused unless the request says `allow_reuse_of_destroyed_name` (UI: an explicit checkbox), so a name is not reused by accident.
- Key import exists only when `EKMMOCK_ALLOW_KEY_IMPORT=true` and only in the UI (there is no REST import endpoint). The material is typed into a field that is cleared the moment the dialog submits; it is never echoed, stored in component state after
  submit, logged or audited (the audit entry says type and size only). Imported keys carry an "Imported" badge. Corrupt keys are shown red with the engine's explanation and are not usable (spec 6.2).
- Key detail shows the RSA **public** key as PEM and JWK `n`/`e` (copy buttons) and the registration command `az keyvault key create --hsm-name <hsm> --name <ref-name> --external-key-id <key-name>`; the `<hsm>` placeholder is a text box kept in component
  memory only. Usage counters are shown. Secret AES bytes and RSA private parameters never reach the console (a leak scan covers raw, base64, base64url and hex of both).

### Namespaces and trust
- Prefix rules per spec 4.2 (at most 64 characters of `[A-Za-z0-9/-]`, normalised; empty means `_default`). The same prefix twice is refused; overlapping prefixes are allowed (routing is longest-prefix) with a warning; a warning is also shown when a prefix
  equals a `_default` key name (open question 15). Changes persist atomically to `namespaces.json` and the client-trust union is refreshed at runtime through `ClientTrustProvider` (a test proves a client of a new namespace connects without restart).
- **Delete:** the namespace name must always be typed. A namespace that still has non-destroyed keys is refused (409) unless the request also says `destroy_keys`; then every key is destroyed irreversibly (each with its own `key.destroy` audit entry) before one
  `namespace.delete` entry (`destroyed_keys=N`). Tombstones stay, so names remain reserved. This is the safest option: nothing is destroyed implicitly.
- **Trust import** ("Import Managed HSM client trust"): the input is auto-detected as the JSON of `az keyvault ekm-connection certificate show` (`caCertificates` base64 DER, `subjectCommonName`) or PEM. It is parsed and previewed (CN, and per CA subject, issuer, validity,
  thumbprint) **before anything is saved** (`dry_run` in the API). Warnings: expired, not yet valid, not a CA (a leaf was pasted), issuing CA is not self-signed (trust is by root CA, open questions 18/19), missing CN, and removing the console test CA. Mode `merge` (default)
  or `replace`; the CN allow-list and the CA list can also be edited by hand. The page shows the matching `az keyvault ekm-connection create --host <host> --server-ca-certificate root-ca.pem --path-prefix <prefix>` command. File upload of the JSON is not implemented (textarea only).

### Certificates
- Info comes from `ServerCertificateProvider.Info` (SAN, issuer, subject, chain, expiry, source, last reload error); a warning shows under 30 days. The effective TLS policy (protocol, cipher suites enforced or "not enforceable on this OS") is shown here and on About.
- **Upload** takes a PEM chain plus an unencrypted private key. Validation first (at least one certificate, SAN present, key parses; the provider then checks that the key matches, the server-auth EKU and expiry); a failure keeps the old certificate and shows the error.
  Storage: the files are written atomically to the configured `Tls:CertFile`/`Tls:KeyFile` when those are set, otherwise to `<data>/tls/server-cert.pem` and `server-key.pem` (key with 0600 permissions on Unix). At the next start the managed files are loaded when no
  `Tls` files are configured, before the development certificate. The key is never returned, logged, or audited (the audit entry holds subject and thumbprint).
- **Generate test PKI for an FQDN:** an RSA-2048 root CA plus a 397-day server certificate (SAN = the FQDN), installed with a hot reload and persisted like an upload. **The CA private key is discarded right after signing** (never stored, exposed or downloadable); the
  trade-off is that the server certificate cannot be re-issued from the same root: generate again and re-register the new `root-ca.pem`. The public `root-ca.pem` is kept in `<data>/tls/` and offered for download only while it still issued the served certificate (an
  upload deletes it). While the development certificate is served, the development root CA is offered instead.
- **Console test client** (used by Playground and Replay): a per-process, in-memory ECDSA CA (`EkmMock Console Test Client CA <random>`) and a client certificate with CN `test.managedhsmclient.local`. Nothing is persisted (no key on disk to protect); after a restart a
  new CA exists and namespaces must trust it again (one click in the Playground). In `--dev` a bootstrap trusts it in `_default` at start (as user `system`, audited).

### Playground and the pinned self-call
- Direct mode calls the engine in-process and is not EKM traffic (it never appears in Live traffic). Via-EKM mode sends a real TLS 1.3 mutual-TLS request to `https://127.0.0.1:<ekm port>/<prefix>/...` through the full pipeline, so it shows in Live traffic like any other call.
  `pool_name` is `ekmmock-playground`, with fresh `request_id`/`correlation_id`; the exchange is found in the inspector by its correlation id and linked.
- **Server certificate validation is pinned, not bypassed:** the self-call client accepts exactly one server certificate, compared by SHA-256 thumbprint with `ServerCertificateProvider.Current` at call time (so it follows a hot reload), and a handler restricts requests to the
  EKM loopback origin. A test proves a different certificate on the same port is refused.
- If no namespace trusts the console test CA, no request is sent: the page says so and offers an audited one-click "trust the test CA in this namespace".
- Results show length and a 12-hex SHA-256 fingerprint only; "unwrap this result" proves the round trip with an equal-fingerprint check. Revealing the plaintext follows the inspector gate exactly (masked by default; `EKMMOCK_INSPECTOR_ALLOW_REVEAL=true` and an audit entry first;
  `playground.reveal.denied` otherwise). The user's typed DEK is cleared from component state after submit; nothing secret goes to URL, storage, logs or audit.

### Replay
- The Replay button in Exchange detail is enabled only when the raw body exists (reveal allowed, `CanReplay`), else it stays disabled with the reason. It sends the stored request again through `EkmSelfClient` (same machinery and pinning as the Playground) with the console test client
  certificate; the inspector audits `inspector.replay`. The new exchange is looked up by client CN, key and operation after the original (up to 3 s) and linked. If no namespace trusts the console test CA the handshake fails and the result says so; if the namespace does not trust it
  the 401 note explains how to fix it. The replay uses the test client identity, not the original client's certificate (which the console never has).

### REST API for the CLI (`/api/console/*`) and its CSRF mechanism
- snake_case, source-generated JSON; keys (list/get/create/enable/disable/expire/destroy), namespaces (list/get/create/update/delete, trust import with `dry_run` and `mode`), certificates (info, upload, generate, `root-ca.pem`), audit (list with filters and paging), about and self-test.
  Same console authentication as the pages. Playground and replay are UI-only.
- **State-changing calls** (`ConsoleMutationFilter`) must carry either the antiforgery token (browser) **or** the header `X-EkmMock-Client` with a non-empty value, *and then* the request must have **no `Origin` header and `Sec-Fetch-Site` must not be `cross-site`**. A browser cannot send a
  custom header cross-site without a CORS preflight (the console has no CORS), and browsers always add `Origin`/`Sec-Fetch-Site` to such requests, so a non-browser client (the future CLI, curl) can mutate and a cross-site page cannot. The browser's antiforgery protection is unchanged.
  In `LoopbackOnly` there is no authentication, so the header is the only mechanism and anything on the machine can call the API (as it can open the console). With `EntraId` the CLI will need a bearer token (M8, open question 38).

### About and redaction
- Redaction is by construction: the About page builds an explicit list of effective options; secrets (master key, Entra client secret, uploaded key material) appear only as "set / not set" and no secret value is ever read into the view model. Tests set recognisable fake secrets in
  the environment and configuration and assert that none appears in the page markup, the API or the audit log.
- Shown: version, effective configuration, self-test per test with pass/fail and duration (failing algorithms/keys flagged), master-key status (loaded / dev mode with the red banner), data volume path and sizes (keystore, namespaces, audit, inspector JSONL), TLS policy, listeners,
  inspector status (ring size, dropped), auth mode, runtime (.NET, OS, container hint) and links.

### Other implementation notes
- `ServerCertificateProvider` gained managed files under `<data>/tls/`, `ReplaceAsync(..., source)`, `DevelopmentRootCaPem` and `ServerCertificateSource.ConsoleGenerated`. `ListenerRegistry.EndpointsOf` exposes the listener addresses. The certificate provider and `EkmSelfClient` are resolved lazily so
  hosts without TLS (unit-test hosts) still start.
- The shipped `appsettings.json` seeds `_default`; `Dev:SeedSampleKeys` is still off by default.

### M6: Tests and results
- New: Server.Tests `AdminApiKeysTests`, `AdminApiNamespacesTests`, `AdminApiCertificatesTests`, `AdminApiAuditTests` (with the action walker), `AdminApiSecurityTests`/`AdminApiAboutTests`, `AdminLeakScanTests`, `PlaygroundTests`, `ReplayTests`, `DevModeConsoleBootstrapTests`;
  Console.Tests page tests for Keys, Namespaces, Certificates, Playground (direct, via EKM, replay), Audit log, About, `PageAccessibilityTests` (every field labelled, grids/tables named, live regions), and Playwright browser tests (create key, playground via EKM, live traffic, audit, certificates, contrast in both themes).
- Test infrastructure changes: tests that set process-wide environment variables (fake master key / client secret / reveal switch) run in the non-parallel `ProcessEnvironment` collection, because a host started by another test at the same moment read those variables (this caused flakes in
  `ConsolePortSeparationTests`); Console.Tests raises the thread-pool minimum (real Kestrel servers share the process with bUnit tests that block threads, and a request could stall for tens of seconds on a busy machine) and runs 4 test threads; the browser test of the `root-ca.pem` link fetches
  the href instead of waiting for a browser download event (the browser cancelled downloads when the machine was busy). The M5 tests that asserted the placeholder pages and the "Replay is implemented in M6" stub were updated to the real behaviour.
- Results on Windows: 1529 tests (Crypto 308, Server 966, Console 255), 1524 passed, 0 failed, 5 skipped (the 429 placeholder and the four Linux-only cipher tests). The whole solution was run five times in a row with the default parallel modules: 5 of 5 green (3 to 4.5 minutes each; the machine was shared
  with other work). Before the three test-infrastructure fixes above, runs of the same code failed 1 to 6 tests in about two of three runs, so those fixes matter; one pre-existing mutual-TLS flake in `ConsolePortSeparationTests` was still seen once afterwards (open question 47).
  Linux (container script): Server 966 tests, 0 failed, 1 skipped (the 429 placeholder).
- Visual check: the real app (`--dev`, Playwright Chromium) in light and dark: banner contrast fixed, every new page and the create-key, playground (via EKM), live traffic, audit log, trust import and certificate generation flows exercised; defects fixed (truncated Keys columns, double parentheses in the namespace header, audit column width, text-area width). Screenshots were taken to the temp folder, not committed.

## M7: Limits, fault injection, Prometheus metrics, structured log levels

### Where the code lives
`Ekm/EkmLimits.cs` (concurrency gate, Limits stage, deadline checkpoint), `Faults/*` (rule model, store, Faults stage, descriptions), `Metrics/*` (`EkmMetrics`, Prometheus text writer, options), `Console/Admin/FaultAdminService.cs` + `Console/Pages/FaultsPage.razor` +
the `/api/console/faults` endpoints, and small changes in the dispatcher, handlers, exchange middleware (log level, metrics), inspector record (fault facts, "closed by server") and console (banner, badges, navigation).

### Pipeline order
`Capture → Exchange → Route → Faults → Auth → Limits → Dispatcher → handlers`, as spec 7. The stages split the work of a fault by what it needs:
- **Faults** (before Auth): evaluates the rules once for the routed request and answers the faults that need neither a body nor a concurrency slot: HSM offline (503), error rate (429/500/503), close connection (abort). Those are *terminal*: they are recorded on the exchange and counted (`Fired`) at once.
  The other kinds (delay, key disabled, blackhole) are only *pending* on the exchange (`PendingFault`) and are recorded and counted **at the moment they act**: blackhole in the Limits stage, delay in the dispatcher right before the engine call, key disabled in the handler after the unknown-key check.
  So a request that Auth rejects (401), or that fails validation before the delay point, or a "disabled" key that does not exist (404), carries no fault badge and does not raise the rule's fire count. Tests pin all three (`ABlackholeAndADelay_OnlyApplyToAuthenticatedCallers…`, `ADelayOrKeyDisabledRule_ThatNeverActedOnARequest…`).
  The delay point is after the request has a valid `request_context` and the HSM is available, so handler-level rejections (bad base64, unknown key, bad algorithm) are delayed like a remote HSM that validates after the round trip.
  An anonymous caller therefore sees 503 for an offline HSM (as Managed HSM would see an offline HSM) instead of 401; the exchange records the TLS-presented certificate CN (`PresentedCommonName`) as client CN in that case, since Auth has not run. `Faults` only runs on the EKM branch, so the console, `/healthz`, `/readyz` and `/metrics` can never be affected (tests walk them with every kind active).
- **Limits** (after Auth): takes a concurrency slot or answers 429, creates the deadline, and carries out a **blackhole inside the slot**.
- **Dispatcher**: the deadline checkpoint (`EnterCryptoStage`), the **delay** and the **key-disabled** answer happen here, right before the engine call.
- Consequence of the split: blackhole and delay (which must hold a slot) only affect authenticated callers; an unauthenticated caller gets 401 and cannot pin a slot. Tests pin this.

### Limits and the internal deadline (spec 10.1)
- `Limits:InternalDeadlineMs` (default 200), `Limits:MaxConcurrency` (default 64), `Limits:LatencyBudgetMs` (250) and `Limits:LatencyWarningMs` (150) are validated at start (deadline and concurrency at least 1).
- **Concurrency**: `ConcurrencyGate` is a lock-free compare-and-swap counter: it takes a slot or says no, never waits and never blocks a thread; there is no queue. It can never show more than the limit (an increment-then-undo design showed 9 of 5 in a contention test, which would have made the
  in-flight gauge lie). The slot is released in a `finally` of the Limits middleware, so an exception, a 4xx/5xx, a client abort or a blackhole that ends all release it. Over the limit is an immediate `429 TooManyRequests` (ProxyError), measured at well under 50 ms in process and under 250 ms over real TLS.
- **Deadline**: each admitted request gets a `CancellationTokenSource` linked to `RequestAborted` with `CancelAfter(deadline - time already spent)`, disposed with the request (`using`), so it never leaks and never outlives the request. The deadline is measured from the **start of the exchange**, not from the Limits stage. It guards the way **to** the engine:
  (1) the body read uses the deadline token: a body that is still arriving when the deadline passes is answered `429` at the deadline, not when a slow client finishes (the exchange record shows total time at the deadline; some HTTP clients, including .NET's, only surface the early response after they finished sending, which is a client matter);
  (2) `EnterCryptoStage` throws 429 when the deadline has passed by the time the operation would start. Crypto is synchronous and **never cancelled**: a call that ends after the deadline still returns its result.
- **`ekmmock_budget_exceeded_total{op}`** counts the internal deadline being missed: a crypto call that ended after the deadline (result still returned) or a request refused with 429 because the deadline had passed before the crypto started. It is not the 250 ms colour: a 300 ms request with a 5 s deadline is red but not "exceeded". This is how the spec's
  sentence is implemented; the red/amber/green status stays the inspector's budget colour.
- **Injected delay vs the deadline**: the delay is applied **after** the deadline checkpoint, and is not cancelled by the deadline. It stands for the distance to a remote HSM (part of the "crypto call"), which is what spec 14 test 26 needs: "delay 300 ms → the client sees more than 250 ms, the budget metric increments, the exchange is red with the fault badge" only works if the delayed request is still answered
  (with the 200 ms deadline, checking after the delay would answer 429 and the crypto time would not be small). Delays are `Task.Delay` on the exchange's `RequestAborted`; no thread is blocked (a test holds 40 delayed requests while others are served in milliseconds).
- **"Queue wait"** in this implementation: EkmMock has no queue, so the field that the spec lists is defined as the server time between the start of the exchange and the start of the crypto stage that is **neither authorization nor injected delay**: reading the request (including a slow client's body), routing, parsing and scheduling latency. The Timing waterfall
  therefore reads queue + auth + delay + crypto + other = total. A slow body shows up as queue wait (tested against a real listener).
- Kestrel limits of spec 5.5 (2 s header timeout, 120 s keep-alive, 16 KiB body) are unchanged and their M3 tests still pass.

### Fault injection (spec 10.2)
- **Gate**: `EKMMOCK_ENABLE_FAULTS` must be exactly `true` (case-insensitive) in the process environment, read once at start (`EnvironmentFaultGate`), never from configuration. Without it: the store refuses every change (`FaultStoreException`), the service answers `403 FaultsDisabled` (REST) / a read-only page with "disabled", `Resolve` returns nothing, and no rule can exist. Tests replace the gate through DI.
- **Rules**: id (`f1`, `f2`, ... never reused), enabled, kind, scope (namespace / key / op, empty or `*` = any), parameters, description (<= 200 characters, no control characters, shown as text, never logged), optional auto-expiry (`expires_after_seconds`, 1 s to 7 days), creation time, fire count. At most 100 rules.
  Kinds: `delay` (fixed `delay_ms` or uniform `min_ms`-`max_ms`, 0 to 60 000 ms), `error` (`error_percent` 0-100, `status_code` 429/500/503 with codes TooManyRequests / InternalError / HsmUnavailable), `offline`, `key_disabled`, `blackhole`, `close`.
- **Precedence** (deterministic, documented on the page): an active **HSM-offline** rule overrides everything and ignores scope (it is process wide: a scope on it is dropped by the store and refused by the API). Otherwise the matching rules are tried **most specific scope first**: key (weight 4) beats operation (2) beats namespace (1) beats global (0); ties go to the **oldest rule**.
  The **first rule that fires wins**; an error-rate rule whose dice say "not this time" lets the next rule have its turn (so "50 % 503" plus a global "delay 100" gives 50 % 503 and 50 % delayed). Exactly one rule acts on a request. `key_disabled` only matches wrap and unwrap (so metadata of a "disabled" key is 200 and the rule did not fire).
- **Dice**: `IFaultRandom` (default `Random.Shared`); tests use scripted or seeded dice. 0 % never fires and 100 % always fires whatever the dice return.
- **Expiry**: a rule with an expiry stops applying at that time and stays listed as `expired` until deleted; the store arms one timer for the next expiry so that the banner and the page update without a click. An expired HSM-offline rule no longer makes `IEngineAvailability` say no.
- **Not persisted**: rules live in memory only and are gone after a restart, on purpose: a forgotten HSM-offline or blackhole rule that survives a restart would silently break a test environment. Nothing is written to the data volume (changes are audited, not stored).
- **HSM offline vs readiness**: `DefaultEngineAvailability` includes the fault (so `info` reflects it, spec 4.6 / 14 test 1) and the Faults stage answers 503 for every operation. **`/readyz` stays ready**: the process is healthy and the fault is a simulation; making readiness fail would make an orchestrator remove or restart the very target the user wants to observe.
  The fault is visible in `/api/console/status` (`faults_active`, `hsm_offline_fault`, `faults_enabled`) and the banner. Test: offline on, `/readyz` 200.
- **Blackhole**: after authentication and inside the concurrency slot, `await Task.Delay(Timeout.InfiniteTimeSpan, linked token)` where the token is `RequestAborted` + `ApplicationStopping` + an optional hold cap (`Faults:BlackholeMaxHoldSeconds`, default 600, 0 = unlimited). No thread is held. **A blackholed request holds a concurrency slot while it is pending** (a hung HSM does exactly that: enough of
  them make the next request answer 429, which is also how spec 14 test 27 is made deterministic) and releases it when the client gives up (aborted connections included), when the cap is reached (the connection is then aborted and the record says "closed by the server") or when the host stops. The exchange is still recorded with status **499**, `ClientAborted`, the fault badge and the real duration.
- **Close connection**: `HttpContext.Abort()` in the Faults stage (before Auth, no slot). The client sees a reset or "response ended prematurely". The exchange is captured with status 499, `ClosedByServer` and the badge.
- **499**: the status recorded (log, inspector, metrics, console text "499 No response") for an exchange that never got an HTTP response; the existing mapping for a client that went away is reused.
- **Key disabled**: the handler answers `403 KeyDisabled` with the engine's own wording after the syntax checks and an unknown-key 404 check (a read-only metadata lookup), so unknown keys, bad algorithms and bad bodies behave as for a really disabled key. The key store file is byte-for-byte unchanged (test).
- **Console and API**: `GET/POST /api/console/faults`, `GET/PUT/DELETE /faults/{id}`, `POST /faults/{id}/enable|disable`, `POST /faults/clear`, `POST /faults/presets/{id}` (presets: distant HSM 100/200/260 ms, HSM offline, 50 % 503). Same console authentication, same `ConsoleMutationFilter` CSRF mechanism as M6 (antiforgery token, or the `X-EkmMock-Client` header without an `Origin`).
  Every change writes an audit entry (`fault.create|update|delete|enable|disable|clear|preset`, target `fault:{id}` or `fault:*`, detail = kind, parameters, scope and expiry, never the description). Validation lives in `FaultAdminService` only (messages name the field), so the page and the API say the same words.
- **UI**: the **Fault injection** page (nav entry enabled, M7 placeholder removed): state alert, presets, add/edit form with per-kind fields and live validation, rule table (state, kind, scope, parameters, fired, expiry, description; enable/disable/edit/delete), clear all, and a short "how rules are applied" card. Read-only with a "disabled" alert without the switch. The **banner** is now driven by the real status (active rule count, HSM-offline sentence, link to the page).
  **Live traffic** shows `fault: <summary>` badges (for example `fault: delay 300 ms`, tooltip with the rule id and description); the Exchange detail shows the badge and rule and a "delay" segment in the Timing waterfall; status 499 reads "499 No response".

### Metrics (spec 9)
- **Exporter choice: a hand-written Prometheus text writer over in-process aggregates, no dependency.** Reasons: (1) the repository rule "keep NuGet dependencies minimal and pinned" and "no outbound telemetry"; (2) `OpenTelemetry.Exporter.Prometheus.AspNetCore` is pre-release (and drags the OpenTelemetry SDK); `prometheus-net.AspNetCore` adds a third-party metrics registry and its own HTTP integration;
  (3) the format is small and fully specified, and the spec's histogram buckets must be exact, which is easiest when we own the histogram; (4) no new package means nothing new for `dotnet list package --vulnerable`. `EkmMetrics` aggregates with lock-free counters and also publishes the same numbers through `System.Diagnostics.Metrics` (meter `EkmMock`) for `dotnet-counters`; there is no push exporter.
- **Names, labels, buckets** exactly as spec 9: `ekmmock_requests_total{op,status,namespace}`, `ekmmock_request_duration_seconds{op}` with buckets 0.005, 0.01, 0.025, 0.05, 0.1, 0.15, 0.2, 0.25, 0.5, 1 (+Inf), `ekmmock_crypto_duration_seconds{op,alg}`, `ekmmock_budget_exceeded_total{op}`, `ekmmock_tls_handshake_failures_total{reason}` (the M3 counter, now exposed),
  `ekmmock_inspector_dropped_total` (M4), `ekmmock_inflight_requests` (gauge, requests holding a slot). The spec gives no buckets for the crypto histogram; the request buckets start at 5 ms, far above a software HSM's microseconds, so it uses 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.
  The crypto histogram records only calls that reached the engine (metadata included, with `alg="none"`), never the injected delay.
- **Cardinality rules** (a test with hostile input proves them): `op` is one of the four wire names or `unrouted`; `status` is a three-digit status the server produced (else `other`); `namespace` is a configured namespace name (at most 256 distinct values, then `other`) or `unknown`; `alg` is one of the four supported names (exact match), `unsupported` or `none`; `reason` is a `HandshakeFailureReason` label.
  Key names, client common names, request text and exception text are never labels.
- **Endpoint**: `GET /metrics` on the **console port only** (the EKM port answers the usual ProxyError 404 for every method), `text/plain; version=0.0.4`, `no-store`. It follows the console authentication like every console route (LoopbackOnly: local connections; EntraId: an allowed signed-in user) unless the documented option `Metrics:AllowAnonymous=true` is set, which opens `/metrics` only (a Prometheus scraper cannot sign in with Entra ID).
  Series are written in a stable order, so two renders of an idle process are identical.

### Structured log levels (spec 9)
- The request log line keeps its fields and gains `fault` (`<rule id>:<kind>`), with real `injected_delay_ms`. Level: **Information** up to and including `LatencyWarningMs` (150), **Warning** strictly above it, **Error** strictly above `LatencyBudgetMs` (250), or when an unexpected exception occurred. The thresholds are the options that colour the budget indicator.
  A client-aborted blackhole is logged at its real duration, so it is typically an error line; that is intentional.
- A redaction test runs every fault kind, the concurrency limit, rejected and unauthenticated requests and a TLS failure on a real host with an Entra console, captures logs down to **Trace** (every category, Kestrel and framework included), and scans logs, the metrics text and the inspector export for every DEK, the imported key material, the RSA private parameters, the master key and the Entra client secret as raw text, base64, base64url and hex.

### Windows key-container leak (open question 46)
- Findings: a PFX re-import without `EphemeralKeySet` creates a key file in `%APPDATA%\Microsoft\Crypto\Keys` that is deleted **only when the `X509Certificate2` is disposed**; neither a GC nor a process exit removes it (probe: three undisposed certificates left three files, three disposed ones left none). `EphemeralKeySet` is **not usable for TLS on Windows**: SChannel refuses it
  ("Authentication failed because the platform does not support ephemeral keys", probed for EC and RSA, with and without `Exportable`). So the fix is to avoid persisted keys where nothing needs them and to dispose deterministically everywhere else.
- Changes: `EkmMock.Pki` creates **CA certificates with ephemeral keys** (CAs only sign), leaf certificates (server, client) keep a regular container and must be disposed; `ServerCertificateProvider` tracks retired snapshots and disposes them when the provider is disposed instead of waiting for a grace-period task that a stopping host never runs; test hosts dispose the server certificate they issue to write PEM files;
  M7 tests share one real host (`FaultsHostFixture`, `MetricsHostFixture`) instead of one per test. A guard test (Windows only) proves that creating and disposing a CA and its leaves leaves no key file behind. Measured: +113 files per full run before, +9 now (open question 46).
- What cannot be removed: a process that is killed (the browser tests kill the spawned `--dev` server) leaks the keys of its server certificate, console test identity and generated certificate (about three files) because no code runs at a kill; and a leaf certificate that a test or user never disposes. Existing files in that directory are never touched by the tests (they include the user's own keys).

### M7: Tests, flakiness and results
- **Totals** (Windows, `dotnet test EkmMock.sln`, final code): 1737 tests, 1733 passed, 0 failed, 4 skipped (the four `CipherPolicyTests.Linux_*` tests, which need OpenSSL; the former 429 placeholder is now a real test). **Linux** (`tests/run-server-tests-linux.ps1 -NoBuild`, container, Server project): 1131 tests, 0 failed, 4 skipped (the four Windows-only `WindowsKeyContainerTests`); the cipher tests and the 429 test ran there.
- **Flake runs** (full solution, Windows, consecutive): three series of five on the code as it evolved, then one final run. Failures seen and what they were: a stale-record match and a 1 s blackhole hold cap that was too short under load (both test-side, fixed: the fixture cap is 4 s and the match requires `ClosedByServer`); a 170 ms delay that ran past 250 ms under load (the end-to-end level tests now use delays far from a boundary; the boundaries are pinned by `LevelFor`);
  a blackhole test that used a 600 ms client timeout, which on a loaded machine could expire before the request reached the blackhole stage (the test now waits until the rule has fired, then aborts the client); delay lower bounds with 2 to 10 ms of margin (Linux `Task.Delay` fired 6 ms early; loosened); a pre-existing M5 bUnit race in `LiveTrafficTests.Pause_...` (resume re-renders asynchronously; the test now waits); and the open-question-47 handshake flake   (3 of 21 runs;
    see OPEN-QUESTIONS 47). On Linux the full container run once showed three load-related failures (two of them fixed as above, a `HostCompositionTests.ADisposedBackend...` first request that did not return 200 once and did not recur in two further container runs, cause not found); the last full container run was green.

## M8: `ekmmock` CLI, conformance suite, bench

### Structure and references
- `src/EkmMock.Cli` (assembly and tool command `ekmmock`, `PackAsTool`, version 0.2.0), `tests/EkmMock.Cli.Tests`. **References**: `EkmMock.Pki` (certificate generation for `certs`) and `EkmMock.Crypto` (master key size and key-name rules for `init`). It does **not** reference `EkmMock.Server`; the console API DTOs are small duplicated records with source-generated JSON (`ConsoleApiModels`, `OutputModels`).
  Packages (pinned in `Directory.Packages.props`): `System.CommandLine` 2.0.14 and `Azure.Identity` 1.21.0 (device-code sign-in only). No other third-party dependency; JSON uses source generation.
- Commands: `init`, `certs ca|server|client|dev`, `key list|show|create|enable|disable|expire|destroy`, `trust import`, `ns list|create|delete`, `faults list|preset|delete|clear` (the last two groups were trivial, so they are included), `test conformance|bench`. Every command has `--help` with examples; `--version`; `--verbose` shows exception details (never secrets), otherwise no stack traces.
- **Exit codes** (printed in every `--help`): `0` success, `1` failure (action refused by the server, a conformance test or bench threshold failed), `2` usage error (bad command line), `3` connection or authentication error (TLS failure, 401/403 from the console, nothing listening, preflight failure).
- Output: tables by default, `--json` / `-o json` for scripting. Secret material is never printed: the API does not return it; `init` prints a master key only with an explicit `--print`; private keys are written to files, never to stdout.
- System.CommandLine 2.0.14 quirks handled: help is wrapped (the help builder is not public) so long descriptions print their details after the standard help; validators run before defaults (the code uses `TryGiven`/`IsGiven`, never `GetValue` in validators); `--help` and `--version` win over parse errors.

### `init`, `certs`
- `init --data <dir>` creates `<dir>`, `tls/`, `inspector/`, writes `master.key` (32 random bytes, base64) with **owner-only permissions** (Unix mode 600 at creation; on Windows a `FileSecurity` ACL for the current user only, set at creation so the key is never readable by others even for a moment; a partial file is deleted on failure) and prints the `EKMMOCK_MASTER_KEY_FILE` instructions.
  It refuses to overwrite an existing `master.key`; with `keystore.json` present and no master key it refuses too (a new key could never open that store); `--force` replaces a master key only when **no** `keystore.json` exists. Re-running `init` on a complete folder changes nothing and says so (idempotent).
- `certs` is **test PKI only** and says so loudly. `ca` writes the root CA certificate and key, `server` a leaf with the FQDN as SAN (extra SANs, validity options), `client` a leaf with the clientAuth EKU and the given CN, `dev` a CA + server certificate + a fake Managed HSM client CA + client certificate in one go (spec 11.2) and `root-ca.pem` for `--server-ca-certificate`. Keys are written owner-only and never printed.
  Generated CA subject names carry a random 8-hex tag so that two generated CAs never collide in the Windows certificate store (open question 25).

### Console access from the CLI
- `--console` (default `https://127.0.0.1:8080`, env `EKMMOCK_CONSOLE`). **Trusting the console's certificate**, in order of preference: `--console-ca <pem>` (the only roots trusted), `--console-pin <sha256>` (pin of the console certificate, no chain needed), `--insecure-console-cert` (accepted **only for a loopback host**, with a warning; there is no blanket bypass for other hosts).
- **LoopbackOnly**: every request carries `X-EkmMock-Client: ekmmock-cli` and never an `Origin` header (the M6 CSRF-safe mechanism for non-browser clients).
- **EntraId** (answer to open question 38): the console API accepts a **bearer token on `/api/console/*` only**. Server side: `ConsoleAuth.AddEntra` registers a policy scheme that forwards to the JWT bearer scheme (`AddMicrosoftIdentityWebApi`) only when the path is `/api/console/*` **and** an `Authorization: Bearer` header is present; everything else (Blazor pages, `/_blazor`, the EKM port) keeps OIDC + cookie
  and ignores bearer tokens (tests prove a valid token is rejected there). The same allowed-object-id / group policy as the UI applies. `ConsoleMutationFilter` treats a bearer-authenticated request as the non-browser proof (no antiforgery token, no header needed). Identity.Web requires an `scp` or `roles` claim in the token, so the app registration must expose an API scope; the CLI's default scope is `api://<client-id>/.default`.
  CLI side: `--auth entra --tenant <id> --client-id <id> [--scope <scope>]` uses `DeviceCodeCredential` (prints the code and URL to stderr, token cached **in memory only**, no disk cache and no flag for one); `EKMMOCK_CONSOLE_TOKEN` supplies a ready token instead. **Verified only with locally signed JWTs and a fake credential, not against a real tenant** (open question 38).
- Conventions for scripts: `key destroy` needs `--confirm <name>` (the name again; no prompt), `key expire --at <ISO-8601>|--clear`, `key create --ns --name --type aes|rsa --size N` (RSA prints `n`/`e` and the `az keyvault key create --hsm-name <hsm> --name <ref> --external-key-id <key>` command), `trust import --ns --json mhsm-client.json [--dry-run]` (prints the preview and warnings such as a non-root CA; `--pem` for a PEM file).
- **New server endpoint `POST /api/console/keys/import`** (needed by the conformance suite for RFC vectors): as gated as the UI import, i.e. `403` unless `EKMMOCK_ALLOW_KEY_IMPORT` is on; the material is decoded with the same code as the UI, zeroed after use, never echoed and never audited. The M6 test that said "no import endpoint" now asserts 403 without the switch.

### Conformance suite (`ekmmock test conformance`)
Acts as the fake Managed HSM: mTLS, TLS 1.3, `--client-cert/--client-key`, `--ca` the **only** trusted root (no insecure mode). 49 checks with ids `14.<test>.<letter>` that cover all 27 tests of spec 14; prints `PASS`/`FAIL`/`SKIP` per check with the id and name, a summary and writes `--report` (default `conformance-report.json`: tool version, time, target, environment, per check id/name/status/duration/message; no secrets, no key material).
Exit `0` only if no check failed (a run where everything was skipped exits 0 with a "no test passed" note; a failing preflight `info` exits 3). After a run without failures it prints the `az` commands of spec 15 with FQDN, prefix and key names filled in. `--list` prints the catalog, `--only <id,...>` selects checks.
- All data is synthetic. Temporary keys are named `conf-<run id>-*`, created through the console API (`--console`), and destroyed at the end; anything that could not be destroyed is listed in the report. An independent RFC 3394 / RFC 5649 implementation in the CLI (`ReferenceKeyWrap`) checks the server's AES-KW/KWP output against an imported KEK.
- Inputs that avoid skips: `--console` (+ `--console-ca`) for key management, destroyed/disabled/expired keys, inspector/audit/fault checks and the port checks; `--alt-client-cert/--alt-client-key` (trusted CA, wrong CN), `--rogue-client-cert/--rogue-client-key` (untrusted CA), `--namespace` (a second namespace is created through the console for the other-prefix checks),
  `--replacement-server-cert/--replacement-server-key` for the hot-reload test (it **leaves the replacement served**), the server started with `EKMMOCK_ENABLE_FAULTS=true` (HSM-offline, 429/503 and delay checks) and `EKMMOCK_ALLOW_KEY_IMPORT=true` (RFC vectors), `--allow-disruptive` for the concurrency-limit test (it holds every slot with blackholed requests), `--persistence-state <file>` for the two-phase restart test.
  Without `--console`, `--aes-key`/`--rsa-key` name existing keys for the round-trip checks.
- **Mapping of spec 14 to checks and what can be skipped**:

| Spec 14 test | Checks | SKIP when |
|---|---|---|
| 1 info | 14.1.a, 14.1.b | 14.1.b without `--console` or with faults disabled on the server |
| 2 api-version | 14.2.a, b | never |
| 3 key names | 14.3.a, b | never |
| 4 not found | 14.4.a, b, c | b, c: no `--console` |
| 5 metadata | 14.5.a, b | b: no RSA key (needs `--console` or `--rsa-key`) |
| 6 round trips and sizes | 14.6.a-f | without `--console` they use the keys named by `--aes-key`/`--rsa-key` |
| 7 RFC vectors | 14.7.a, b | server has key import disabled |
| 8 RSA interop | 14.8.a, b | b: key import disabled (client needs the private half) |
| 9 mismatch | 14.9.a | never |
| 10 tamper | 14.10.a | never |
| 11 disabled/expired | 14.11.a, b | no `--console` |
| 12 base64url | 14.12.a, b, c | never |
| 13 persistence | 14.13.a | **always in a one-shot run**: needs two runs around a restart (`--persistence-state`) |
| 14 TLS / auth | 14.14.a-e | c: no `--alt-client-*`; d: no `--rogue-client-*`; e: no `--console` (the second namespace is created through it) |
| 15 hot reload | 14.15.a | no `--replacement-server-*` or no `--console` |
| 16 port separation | 14.16.a, b | no `--console` |
| 17 LoopbackOnly refuses non-loopback | 14.17.a | **always**: needs to start a server (covered by the server tests) |
| 18 no secrets | 14.18.a | no `--console` |
| 19 keystore at rest | 14.19.a | **always**: needs the data folder (covered by the server tests) |
| 20-23 inspector | 14.20.a, b, 14.21.a, 14.22.a, 14.23.a | no `--console`; 14.20.b also needs faults |
| 24 inspector overhead | 14.24.a | **always**: in-process measurement (M4 benchmark test) |
| 25 benchmark | 14.25.a | **always** in the suite: it takes 60 s; use `ekmmock test bench` (below) |
| 26 delay | 14.26.a | no `--console`, or faults disabled on the server |
| 27 429 | 14.27.a | no `--console`, no `--allow-disruptive`, or faults disabled |

  The local end-to-end test supplies every optional input and ends with **49 checks: 44 PASS, 0 FAIL, 5 SKIP** (14.13.a, 14.17.a, 14.19.a, 14.24.a, 14.25.a: the ones that cannot be observed from outside in one run). 14.13.a is covered by a separate two-phase test (`PersistenceRestartTests`) that runs the suite, restarts the real server and runs it again.
  The suite can fail: negative tests point it at a server with the HSM-offline fault and at a stub that answers wrongly, and assert exit 1 and the failing checks.

### Bench (`ekmmock test bench`)
- Closed loop by default: N workers (default 16), each with its own kept-alive HTTP/1.1 connection, sending the next request when the last was answered; 5 s warm-up (discarded), then the measured duration. `unwrapkey` wraps once first with a synthetic DEK. One **preflight** request before the load, so a TLS or trust problem exits 3 instead of producing a run of identical errors.
  `--rate <req/s>` switches to an **open loop** (requests scheduled at a fixed rate, latency measured from the scheduled start, which corrects coordinated omission); the closed loop is documented as *not* correcting it. On Windows the open loop requests a 1 ms timer resolution for the run, and never sends before the scheduled start.
- Statistics: `Stopwatch` timestamps, an allocation-free log-linear histogram (8 sub-bucket bits, at most 0.8 % error; the old per-sample list allocated per request), p50/p90/p99/p99.9/max, req/s, errors by status code (and `exception:<type>`), the share over 250 ms, a bucket histogram, the first slow requests with their offset (tells a periodic stall from noise). `--json`/`--report` for the result; exit 1 on `--assert-p99-ms`, `--max-over-250-pct`, `--assert-no-errors`.
  The DEK is never logged; requests show up in the console like any other traffic.

### Benchmark (spec 14 test 25) - measured
Raw files and machine in `docs/benchmarks/` (README there). Release build, `--dev`, loopback, 8 logical CPUs (i7-9700K), **client and server on the same shared machine**, concurrency 16, 60 s:

| Operation | req/s | p50 | p99 | max | > 250 ms | Target p99 |
|---|---:|---:|---:|---:|---:|---|
| AES `unwrapkey` A256KWP | 30,221 | 0.41 ms | 1.56 ms | 327 ms | 16 of 1.8 M | < 10 ms: **met** |
| RSA-2048 `unwrapkey` | 9,367 | 1.45 ms | 4.32 ms | 340 ms | 16 of 562 k | < 30 ms: **met** |
| RSA-4096 `unwrapkey` | 1,894 | 8.19 ms | 18.7 ms | 171 ms | 0 | < 100 ms: **met** |
| `info` | 32,625 | 0.37 ms | 1.62 ms | 315 ms | 16 of 2.0 M | < 5 ms: **met** |

- **The "0 % over 250 ms" target is not met strictly**: 0.001-0.003 % of the requests (16 per run, all at once) are one ~100-340 ms stall roughly every 10 s at 30k req/s. Open loop at 1,000 req/s: AES p99 5.5 ms, nothing over 250 ms; at 5,000 req/s: p99 36 ms (stall-aware), nothing over 250 ms. Root cause not isolated (see the benchmarks README and open question 55).
- **Two real server inefficiencies were found and fixed by this measurement** (first run: 331 req/s, p50 47 ms, p99 101 ms): (1) `MtlsCallerAuthorizer` built an `X509Chain` for every request (12 ms on Windows, 99 % of the time of an `info`): successful verdicts are now cached per (certificate thumbprint, namespace, presented intermediates). The cache entry is tied to the exact `NamespaceTrust` instance (any trust change publishes new instances and kills every entry),
  is only used while `now` is inside the validity window of the leaf and of **every chain element** (expiry is still judged per request), and only successes are stored (a client that fixes its certificate is accepted at once). Common name checks and everything else still run per request. Tests: `MtlsChainVerdictCacheTests` (one build for repeated calls, failures not cached, trust change invalidates, expiry, namespaces separate, CN list still enforced).
  (2) The console logger's default queue mode (`Wait`) made request threads wait for stdout (about 0.4 ms per line, serialised): now `QueueFullMode=DropWrite` with `MaxQueueLength=16384`, so under extreme overload **log lines can be dropped** instead of slowing requests (open question 54). Result: 331 to about 30,000 req/s and p99 from 101 ms to 1.5 ms.
- `ServerGarbageCollector=true` and `ConcurrentGarbageCollection=true` are set in `EkmMock.Server.csproj` (spec 11.1).

### M8: Tests and results
- **Totals** (Windows, `dotnet test EkmMock.sln`, final code): 2030 tests, 2026 passed, 0 failed, 4 skipped (the four `CipherPolicyTests.Linux_*` tests, which need OpenSSL). Per project: Server 1177 (1173 + 4 skipped), Cli 247, Console and Crypto the rest. **Linux** (`tests/run-server-tests-linux.ps1`, container, Server project): 1177 tests, 0 failed, 4 skipped (the four Windows-only `WindowsKeyContainerTests`), so the cipher tests, the bearer tests and the chain-cache tests ran there.
- **Flake runs**: five consecutive runs of the Server project (1177) and the CLI project (247) on the final code: all 10 runs green, no flake seen (the known open-question-47 flake did not occur). `dotnet list package --vulnerable --include-transitive` is clean for all projects.
- New: `EkmMock.Cli.Tests` (247 tests: parsing/help, `init`, `certs` (SAN, EKU, chain built and verified, keys never printed), formatters, exit codes, `--confirm`, device-code with a fake credential, console client against stubs, histogram and bench statistics, reference key wrap, catalog, and **real-server integration**: `key` and `trust` commands against `/api/console/*`, the full conformance run, the persistence restart, a bench run, the leak scan and the negative tests),
  and in `EkmMock.Server.Tests` `ConsoleBearerTests` (fake JWT validation: policy, 401/403, bearer rejected on pages, `/_blazor` and the EKM port), `AdminApiImportTests`, `CliBearerEndToEndTests` (the CLI against an in-process EntraId console) and `MtlsChainVerdictCacheTests`.
- **Leak scan**: stdout, stderr and the JSON report of a full run (and the bench output) are scanned for every DEK, AES key, RSA private parameter and the master key as raw text, base64, base64url and hex.
- Linux: the CLI project is built by `tests/run-server-tests-linux.ps1` (the Server tests reference it); the CLI tests themselves spawn the built server and are run on Windows only.

- **CNG key files** (`%APPDATA%\Microsoft\Crypto\Keys`): +113 per full solution run on the M6 code (baseline copy), **+9 per full run now** (+11/+12 in the runs that had failures), Server.Tests alone +2.

### M7: Not covered / deliberately skipped
- No persistence of fault rules, no per-rule schedules and no "latency ramp"; one rule acts per request (no stacking of a delay with an error).
- No real Managed HSM behaviour is claimed: what Azure does on a 429, a blackhole or a close is an end-to-end question for `docs/RESULTS.md` (open question 48).
- `/metrics` has no authentication of its own beyond the console's; no TLS client auth for scrapers.

## M9 (1/2): Docker image, compose, health check, container-safe console binding, CI

Scope of this half: image, compose, health check, the console-binding conflict, Makefile/PowerShell targets and GitHub Actions. Bicep, `e2e.sh`, README, RUNBOOK and RESULTS are the second half.

### Image (`deploy/docker/Dockerfile`)
- **Bases**: `mcr.microsoft.com/dotnet/sdk:10.0-noble` builds, `mcr.microsoft.com/dotnet/aspnet:10.0-noble` runs. Ubuntu 24.04 with **OpenSSL 3.0.13** (checked in the image), not Alpine, distroless or chiseled (spec 3, 5.1: cipher-suite control). Both are pinned by **tag and digest** in literal `FROM` lines (the multi-arch index digests of 2026-11-09; Dependabot's docker ecosystem updates them). The `-noble` suffix is a deliberate refinement of the spec's `:10.0` so that the distribution cannot change under a floating tag.
  Runtime 10.0.14. A static test (`DeploymentFilesTests`) pins: two stages, tag and digest, no `latest`, no alpine/distroless/chiseled, exactly one `USER $APP_UID`, health check, volume, ports, no secret-looking `ARG`/`ENV`.
- **Build**: the restore layer copies only `global.json`, `Directory.*.props` and the four `.csproj` files (a source change does not re-download packages); `PublishReadyToRun=true` is set at restore time too (it adds the crossgen2 and runtime packs). The server and the CLI are published **framework-dependent, ReadyToRun, `linux-x64`** (`ARG RID` for arm64), `.pdb` files deleted. Image size **417 MB** (the aspnet base is about 220 MB; the rest is the Fluent UI and Identity.Web assemblies and the R2R code).
- **Allow-list `.dockerignore`**: `*` first, then `!global.json`, `!Directory.*.props`, `!src/**`, then bin/obj, `.env*`, `*.pem`, `*.key`, `*.pfx`, `master.key`, `keystore.json`, `*.jsonl` again inside `src`. The context cannot contain tests, docs, `.git`, benchmarks, data or keys. A scan of the finished image finds no `.pem`/`.key`/`.env`/`master.key`/`keystore.json` (only the system's `/usr/lib/ssl/cert.pem`).
- **Server and CLI**: the server in `/app`, the CLI in `/app/cli` with `/usr/local/bin/ekmmock` -> `/app/cli/ekmmock` (the apphost; it finds the shared runtime in `/usr/share/dotnet`). `ekmmock` is the health probe and the in-container test client.
- **User and file system**: `USER $APP_UID` (1654, defined by the base image); `/app` is root-owned and read-only to the app; `/data` (`chown 1654`, mode 750) is declared `VOLUME` and is the **only** writable place. Verified with `docker run --read-only --cap-drop ALL --security-opt no-new-privileges -u 1654` and in compose: `id` = 1654, `CapEff`/`CapBnd` = 0, `NoNewPrivs` = 1, writes to `/app`, `/etc`, `/usr`, `/home/app` fail with "Read-only file system", `/data` is writable. The server runs **without any tmpfs**: a run with `--read-only` and no `/tmp` mount served the console, created keys and generated a CA with no write error.
- **Configuration**: the shipped `/app/appsettings.json` is the repository's own (LoopbackOnly console on `127.0.0.1`, EKM on `0.0.0.0:8443`, `Data:Path=/data`, `Dev:Enabled=false`, no secrets, no sample keys, no namespaces trusted), which is already production-safe, so no separate container settings file exists. Everything container-specific is an environment variable (compose or `docker run -e`). The image does **not** bake `EKMMOCK_CONSOLE_CONTAINER_PUBLISH` or a non-loopback console URL: a bare `docker run` has a console reachable only from inside the container (`docker exec ... ekmmock ...`, the health probe), which is the safe default; compose opts in explicitly.
  Secrets (`EKMMOCK_MASTER_KEY_FILE`, `EKMMOCK_CONSOLE_CLIENT_SECRET[_FILE]`) are only ever run-time environment or files, never `ARG`/`ENV` in the Dockerfile (a test scans for it).
- **Runtime environment**: `DOTNET_gcServer=1` (also `ServerGarbageCollector` in the project; spec 11.1, DECISIONS "M8: Benchmark"), `DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1` (the project sets `InvariantGlobalization` too; there is no ICU in the image and nothing depends on culture data), `DOTNET_EnableDiagnostics_IPC=0` (no diagnostics socket in `/tmp`), `ASPNETCORE_HTTP_PORTS=` (**cleared**: the base image's default plain-HTTP `:8080` listener would collide with the console port, and EkmMock has no plain-HTTP mode).
  **GC measured, not assumed**: idle RSS after start is about **130 MB with `DOTNET_gcServer=1` and about 130 MB with `=0`** on an 8-CPU Docker Desktop VM (docker stats 52 MiB working set in both), so Server GC costs nothing at idle here; `DOTNET_GCHeapCount`, `GCConserveMemory` and `TieredPGO` are left at their defaults (M8 ruled tiering/PGO out as a cause of the stalls; no data supports a change). The runtime honours container CPU and memory limits (heap count follows the CPU limit); re-measure on the 2-vCPU target (open question 64).
- **Entry point**: `ENTRYPOINT ["dotnet", "/app/EkmMock.Server.dll"]`, `CMD []` (so `command: ["--dev"]` works), `STOPSIGNAL SIGTERM` (graceful host shutdown), labels `org.opencontainers.image.{title,description,source,url,documentation,licenses,version,revision,base.name}`; `licenses` is `NOASSERTION` because the repository has no licence file (open question 66). `EXPOSE 8443 8080`.
- **ASP.NET Core Data Protection keys** (antiforgery tokens, and the sign-in cookie in EntraId mode): they live in `/data/dataprotection` so that **open consoles survive a restart** (verified: the key file persisted across `docker compose restart`). The framework's `FileSystemXmlRepository` writes every key through `Path.GetTempFileName()`, i.e. `/tmp`, which fails with a read-only root file system and no tmpfs (the first container run logged `Read-only file system: '/tmp/'` and the key ring could not be created), so it was replaced by `DataFolderXmlRepository`:
  the temporary file is created next to the final one, mode 600 on Unix, atomic rename. If the folder is not writable the keys are held in memory (`InMemoryXmlRepository`, a warning is logged) and tokens die with the process. The keys are **not encrypted at rest** (no XML encryptor; ASP.NET logs a warning at start): whoever reads the volume can already read the key store (open question 63). Tests: `DataProtectionKeyFolderTests`.

### Health check (`ekmmock health`)
- The runtime image has no `curl`/`wget`, so the probe is a CLI command: `ekmmock health [--console <url>] [--ready] [--timeout 3s] [--console-ca <pem> | --console-pin <sha256> | --insecure-console-cert]`. It GETs `/healthz` (or `/readyz` with `--ready`) and exits **0 only for HTTP 200 with the body status `alive`/`ready`**, **1** for everything else (connection refused, TLS failure, timeout, any other status or body), 2 for a usage error. Docker reads 0 as healthy and 1 as unhealthy (2 is reserved), which is why connection errors are 1 and not the CLI's usual 3.
  One short line on stdout/stderr, never a secret; the console URL defaults to `$EKMMOCK_CONSOLE` (the image sets `https://127.0.0.1:8080`), the timeout to 3 s (also the connect timeout).
- TLS trust is the same helper as every console call. The image's `HEALTHCHECK` uses `--insecure-console-cert`, which the command (like the console client) **accepts for loopback URLs only**: the probe talks to 127.0.0.1 inside its own network namespace, so there is no path for a man in the middle, and `/healthz` stays info-minimal (`{"status":"alive"}`, nothing about keys, version or configuration). It does not prove which certificate is served (open question 62).
  `HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3`. The EKM port is not a health endpoint (404, tested): `/healthz` exists on the console port only.
- Tests (`HealthCommandTests`, 33): healthy, `--ready`, every non-200, wrong or missing body, unreachable, timeout (returns promptly), URL defaults and authority-only requests, non-https and bad timeout are usage errors, `--insecure-console-cert` refused for a non-loopback URL **before anything is sent**, and against the real server over real TLS with the CA, with the pin and with the loopback switch, plus an untrusted CA, a wrong pin, no trust option (the OS store does not know the dev CA), a closed port, and the EKM port.

### Port 443 for non-root (open question 6)
Measured in the real image (details in OPEN-QUESTIONS 6): with Docker's default `net.ipv4.ip_unprivileged_port_start=0` a non-root user with **all capabilities dropped binds 443** (`Endpoints__Ekm__Url=https://0.0.0.0:443`). With the sysctl at 1024 the bind fails (`Permission denied`, exit 139) even with `--cap-add NET_BIND_SERVICE` and even without `no-new-privileges`; `--sysctl net.ipv4.ip_unprivileged_port_start=443` works again.
The image and compose keep **8443 inside** and map `443:8443` (what the spec's VM flow needs); 443 inside is the ACI case and **is not verified in ACI**. Fallback order: VM or 8443 mapping, the sysctl, root in ACI only as a documented deviation. Nothing runs as root by default.

### Container-safe console binding (open question 33): a deliberate deviation that resolves a conflict inside the spec
**The conflict**: spec 5.4 and 14 test 17 require the app to refuse `Console:Auth=LoopbackOnly` with a non-loopback bind, and spec 11.2/5.4 publish the console as `127.0.0.1:8080:8080`. Inside a container a loopback-only bind is unreachable from a published port (the traffic arrives on the container's bridge address), so both cannot hold. The strict rule stays the default everywhere; one explicit, narrow opt-in is added.
- **Opt-in**: the environment variable **`EKMMOCK_CONSOLE_CONTAINER_PUBLISH=true`** (exactly `true`, any case; `1`/`yes`/anything else is "not requested", it fails closed). It is an environment variable on purpose (like `EKMMOCK_ENABLE_FAULTS` and `EKMMOCK_INSPECTOR_ALLOW_REVEAL`), so it cannot be committed in an appsettings file by accident.
- **What it permits**: a non-loopback console bind (`https://0.0.0.0:8080`) **only if all hold**: `Console:Auth=LoopbackOnly`, and the process is "demonstrably in a container". **Container probe** (`SystemContainerProbe`, injectable `IContainerProbe`): Linux **and** `DOTNET_RUNNING_IN_CONTAINER=true` (set by the .NET images) **and** a runtime marker (`/.dockerenv` for Docker, `/run/.containerenv` for Podman, or `KUBERNETES_SERVICE_HOST`). The variable alone is not enough (anyone can export it on a laptop), the marker file alone is not enough (a stray file); this guards against **accidental** misuse on a host, not against an operator who controls the process environment (such an operator can set `EntraId` or change the configuration anyway).
- **Refusals (host does not start, exit 78, message names the variable)**: the opt-in set outside a container (so the variable copied to a developer machine does not pass silently); the opt-in set with `EntraId` (it never applies to that mode, whose rules are unchanged); and, as before, any non-loopback bind without the opt-in, **including inside a container**. Validated in all three places that validate the console (host builder pre-flight, options validation, Kestrel set-up) with the same probe.
- **When active** (`ConsoleExposure.ContainerPublishActive`: LoopbackOnly, opted in, in a container, non-loopback bind): (1) a startup **warning** ("publish the console port to the host on 127.0.0.1 ONLY ... published on 0.0.0.0 it is an unauthenticated console for the whole network segment"), (2) a **banner on every console page** (`ContainerPublishBanner`, role `alert`, title "Console bound inside a container — host publish must be loopback-only"; field `container_publish` in `/api/console/status`),
  (3) a **runtime source-address check** in `ConsoleRequestGuardMiddleware` for every request: accepted sources are loopback, RFC 1918 (10/8, 172.16/12, 192.168/16), IPv4 link-local, IPv6 ULA (`fc00::/7`) and link-local (`fe80::/10`) and the IPv4-mapped forms of the IPv4 ranges; everything else (public, CGNAT `100.64/10`, multicast, unspecified, NAT64, deprecated site-local) gets **403**. `Console:EnforceLoopbackClient=false` does not turn this check off. The Host-header (DNS rebinding) and Origin checks are unchanged.
- **The source check is defence in depth, not the control.** With `-p 127.0.0.1:8080:8080` the connection arrives from the engine's bridge/NAT address, which is private, so the check cannot distinguish "my laptop through the loopback publish" from "a neighbour through a careless `0.0.0.0` publish": both are private. It blocks only public sources (a public-IP VM published on `0.0.0.0` is reached from the internet with a public source address, and that is refused). **The primary control is the host-side `127.0.0.1` in the port mapping.**
- **Residual risk**: an operator who publishes `0.0.0.0:8080` (or `8080:8080`) exposes an unauthenticated admin console to the whole private network segment. Mitigations: both compose files hard-code `127.0.0.1` in front of the console port (no variable there) with a loud comment, a static test fails when a console mapping lacks `127.0.0.1`, the banner and the startup warning say it, and the VM runbook uses `ssh -L 8080:127.0.0.1:8080`. `EntraId` is the answer for a console that must be reachable from other machines (ACI).
- Tests (`ConsoleContainerPublishTests`, 100 cases): probe matrix (Linux/non-Linux, the .NET marker, `/.dockerenv`, `/run/.containerenv`, Kubernetes, the variable alone), the opt-in parsing (`true`, `TRUE`, `1`, `yes`, `false`, empty), the validation matrix (opt-in on/off x in a container or not x LoopbackOnly/EntraId x loopback and non-loopback binds, other rules not relaxed), the exposure and its warning, 38 source addresses (loopback, 172.17.0.1, 10.x, 192.168.65.1, ULA, link-local, IPv4-mapped, and 8.8.8.8, 100.64.0.1, 172.15/172.32, 2001:db8::, NAT64 rejected), the guard (403 for refused sources, not bypassed by `EnforceLoopbackClient=false`, Host and Origin rules still apply, null remote address for the in-process host), the banner (bUnit, also in the layout) and the real host with a simulated container (starts and reports `container_publish`, refuses without the opt-in as before, refuses the opt-in outside a container and with EntraId, a loopback bind changes nothing).
  `ConsoleStartupValidationTests` (test 17) is unchanged and passes.

### Compose (`deploy/docker/compose.yaml`, `compose.dev.yaml`)
- **`compose.yaml`** (the real one, spec 11.2): one service `ekmmock`; ports `${EKMMOCK_EKM_PORT:-443}:8443` and **`127.0.0.1:${EKMMOCK_CONSOLE_PORT:-8080}:8080`** (the loopback address is fixed text); `/data` is a named volume; `read_only: true`, `tmpfs: /tmp`, `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`, no `user:` (the image's `$APP_UID`), `restart: unless-stopped`, the image's health check; the master key from a **Docker secret file** (`EKMMOCK_MASTER_KEY_FILE=/run/secrets/ekmmock_master_key`, `file: ./secrets/ekmmock_master_key`, created with `ekmmock init --master-key-file`); the certificate is `/data/tls/server.crt`/`server.key`; `EKMMOCK_ENABLE_FAULTS` defaults to false, key import is false.
  Compose file secrets keep the host file's owner and mode (no `uid`/`mode` outside Swarm), so on a Linux host the secret must be readable by uid 1654 (`chown 1654:1654`): written into the file's header. No secret literal anywhere (tested, including a scan for 32-byte base64 values).
- **`compose.dev.yaml`** (standalone, not an override): a laptop try-out. `dev-init` (one-shot, same hardening) runs `ekmmock init` (master key in `/data/master.key`, next to the key store: dev only) and `ekmmock certs dev --out /data/dev-pki --fqdn ekmmock` (SAN `ekmmock, localhost, 127.0.0.1, ::1`) once, and copies the server certificate to `/data/tls` on every start (the server persists an uploaded certificate over its own files, so the originals stay what `certs dev` wrote and the conformance run can repeat).
  `ekmmock` runs `--dev` with `Dev__SeedSampleKeys` (**`aes-key-1` AES-256 and `rsa-key-1` RSA-2048** in `_default`), key import and fault injection switched on (dev only, so the suite skips as little as possible), the console opt-in and `Console__AllowedHosts__0=ekmmock`. `dev-seed` (one-shot) waits for `ekmmock health --ready` and then runs `ekmmock trust import --ns _default --json /data/dev-pki/mhsm-client.json` through the console API (**the fake Managed HSM client CA and CN `test.managedhsmclient.local` are trusted**), which also exercises the container-publish console from another container (private source address, Host `ekmmock`).
  `make compose-up` (`docker compose up -d --build`, then waiting for the seeding container to exit 0 and the server to be healthy) returns when everything is ready (`up --wait` is not used, see "CI"). The generated PKI (client certificates, CA keys) stays in the volume `/data/dev-pki`; copy it out with `docker compose -f deploy/docker/compose.dev.yaml cp ekmmock:/data/dev-pki ./out/dev-certs` (on a Linux host `chown` it afterwards: the files are mode 600, owner uid 1654).
- **The "clean machine" flow** is the conformance suite **inside the container** (`docker compose exec ekmmock ekmmock test conformance ...`, `make conformance`, `scripts\dev.ps1 conformance`): nothing but Docker is needed, the certificates never leave the volume, and the in-container run uses loopback for both ports. The host-CLI flow (`conformance-host` against `make dev`/`dev.ps1 dev`, or the copied certificates) is documented too. Both were run.
- **Makefile and `scripts/dev.ps1`**: the same targets `dev`, `build`, `test`, `image`, `compose-up`, `conformance`, `conformance-host`, `compose-down`, `clean`. `dev` builds the CLI and server, generates the dev PKI into `out/dev/pki` once, `init`s `out/dev/data`, starts a background trust import (waits for `health --ready`) and runs `dotnet run --project src/EkmMock.Server -- --dev` with sample keys, key import and faults on (host ports 8443/8080, `EKMMOCK_EKM_PORT`/`EKMMOCK_CONSOLE_PORT` override). The Makefile was verified with `make -n` in a Linux container (not executed there); the PowerShell script was executed (`dev`, `conformance-host`).

### M9 container verification (real runs on this machine)
All with the image built from this code (417 MB), Docker Desktop 29.9.2 (Linux engine, 8 CPUs), host ports 18443/18080 because the defaults may be taken:
- **Conformance in the compose dev stack: 49 checks, 44 PASS, 0 FAIL, 5 SKIP** (14.13.a one-shot, 14.17.a, 14.19.a, 14.24.a, 14.25.a: not observable from outside, as in M8). **14.13 two-phase across `docker compose restart`: PASS** (a key, a namespace and a wrapped DEK from before the restart unwrap after it; the master key and data are on the volume). The same suite from the host CLI against `scripts\dev.ps1 dev` (`dotnet run`, Windows): 44 PASS, 0 FAIL, 5 SKIP.
- **TLS in the container (OpenSSL)**: a TLS 1.3 client offering only `TLS_AES_256_GCM_SHA384` is accepted, only `TLS_AES_128_GCM_SHA256` accepted, only `TLS_CHACHA20_POLY1305_SHA256` is refused (`sslv3 alert handshake failure`), TLS 1.2 is refused (`protocol version` alert). This is the first place the Linux cipher enforcement was verified in a running product container (the Windows tests skip it).
- **Hardening**: non-root (uid 1654), root file system read-only (writes fail), `/data` and tmpfs `/tmp` writable, all capabilities dropped, `NoNewPrivs`, the process is `dotnet /app/EkmMock.Server.dll --dev`; the console port is bound on the **host's loopback only** (`127.0.0.1:18080 LISTENING`), a request with another `Host` gets 403, console paths on the EKM port and the reverse are 404.
- **Not run**: ACI, a Linux host (the Makefile was only dry-run with `make -n` in a Linux container; the `chown 1654` notes for compose file secrets are from Docker's documented behaviour), `docker scan`/Trivy of the image.
- **Production `compose.yaml` was run too** (certificate and key placed in the data volume, master key from a Docker secret file created by `ekmmock init --master-key-file`): healthy, `dev_mode=false`, `container_publish=true`, the secret mounted at `/run/secrets/ekmmock_master_key`, a key created through the CLI inside the container, `docker stop` took 0.5 s and the process exited 0 (graceful shutdown on SIGTERM). The secret was readable by uid 1654 because Docker Desktop does not map host permissions; on a Linux host it must be `chown 1654:1654` (see the compose header).
- **Line endings**: the repository keeps CRLF files (Git `core.autocrlf=false` here), which breaks a Makefile and shell scripts on Linux. `.gitattributes` forces LF for `Makefile`, `*.sh` and the Dockerfile only; nothing else was renormalised. (The CI simulation below caught this: a CRLF shell script fails with `set: pipefail: invalid option name`.)

### Docker build and restore in this environment
- **The standard path did not work here.** `docker build -f deploy/docker/Dockerfile .` fails in `dotnet restore` with `NU1301` / `SSL Handshake failed ... sslv3 alert handshake failure` for `api.nuget.org` (also with `--dns 8.8.8.8`, and `curl` in the SDK container fails the same way; the host's own NuGet configuration has nuget.org **disabled** and uses a corporate mirror, which the container reaches). `--network host` on Docker Desktop did not help (name resolution failed).
- **What was done**: `ARG NUGET_SOURCE` in the Dockerfile (restore source only; it never reaches the image or a layer's final content), passed as `--build-arg NUGET_SOURCE=<mirror url>` (compose: `NUGET_SOURCE` environment variable; Makefile/`dev.ps1` pass it through). With it the image built in about 60 s (`NU1900` vulnerability-audit warnings did not occur). The mirror URL is environment-specific and deliberately **not** written into the repository.
  Reproduce: `docker build -f deploy/docker/Dockerfile --build-arg NUGET_SOURCE=<feed url or folder> -t ekmmock:local .`. **The unmodified standard path was built successfully by the CI `image-conformance` job** (a GitHub runner reaches nuget.org; run 42713960603), but **not on this development machine**.
- A local-folder restore source (`NUGET_SOURCE=/some/folder` plus a bind-mounted `--build-context`) is possible with the same argument but was not needed.

### CI (`.github/workflows/ci.yml`, `.github/dependabot.yml`)
- **Hardening** (checked against the repository's github-actions-hardening skill, and with actionlint (`rhysd/actionlint`, run in a container) which reported nothing): triggers `push` to `main`, `pull_request` (fork PRs get a read-only token and no secrets by design), `workflow_dispatch`; **no `pull_request_target`/`workflow_run`**; top-level `permissions: contents: read` and the same minimum on every job; every `uses:` pinned to a **full commit SHA with a version comment** (`actions/checkout` v7.0.1 `3d3c42e`, `setup-dotnet` v6.1.0 `0f4a354`, `cache` v6.1.0 `55cc834`, `upload-artifact` v7.0.2 `cf430e0`; each SHA was looked up with `gh api repos/<owner>/<repo>/git/ref/tags/<tag>` and confirmed with `.../commits/<sha>`); `persist-credentials: false` on every checkout; **no `${{ }}` inside any `run:` script** (the shell steps read nothing from the event; a test scans for it); no secrets; a concurrency group per ref with cancel-in-progress; a `timeout-minutes` on every job. A static test (`DeploymentFilesTests`) pins these rules.
- **Jobs**: `build-test` (ubuntu-latest: `dotnet build -warnaserror`, `dotnet test --solution` without `Category=Browser`, the **vulnerability scan**, TRX artifact). The scan runs `dotnet list EkmMock.sln package --vulnerable --include-transitive`, which exits 0 even with findings, so the step greps the output for "has the following vulnerable packages" **and** fails when the advisory source could not be reached (a scan that could not run must not pass). `build-test-windows` (windows-latest, same build and test): the product is developed on Windows, the CNG key-container tests apply only there, and the Linux job covers what Windows skips; a full local run takes 2.5 minutes, so it is cheap; a separate job so that a Windows-only problem never hides the Linux result.
  `browser-tests` (ubuntu-latest: Chromium and its system libraries installed with `playwright.ps1 install --with-deps chromium`, then only `Category=Browser`): a separate job so that a browser download can never fail the other jobs (open question 65). `image-conformance`: builds the image with `make compose-up` (compose `up -d --build`, the **standard nuget.org path**), checks the hardening (uid 1654, read-only root, `/data` writable, `ReadonlyRootfs`/`CapDrop`/`SecurityOpt`, the health command), runs `make conformance` (fails on any FAIL), then the two-phase restart check (14.13) around `docker compose restart`, uploads the reports and logs and always runs `docker compose down -v`.
- NuGet is cached with `actions/cache` keyed on `hashFiles('Directory.Packages.props', 'global.json')`. The SDK is `10.0.x` (the latest, not `global.json`'s floor 10.0.100: the tests need the 10.0.14 shared framework that `Microsoft.AspNetCore.Mvc.Testing` matches). Builds and tests run in **Release** (closer to what ships and less noisy for the timing-sensitive inspector overhead test).
- Dependabot: `nuget` (minor and patch grouped), `github-actions` (grouped) and `docker` (`/deploy/docker`, which also refreshes the digest pins), weekly.
- **Not executed locally**: GitHub Actions cannot run here. The workflow was validated by YAML parsing, actionlint, the static tests, and by running the same commands (`dotnet build -warnaserror`, `dotnet test --solution --filter-not-trait ... --report-xunit-trx`, the vulnerability scan, the compose and conformance steps) by hand. The result of the real runs is recorded in the final report of this milestone.
- **What the first real run found** (run 42712350188 on the first commit): (1) **the image built on the GitHub runner from nuget.org with the unmodified Dockerfile** (the standard path, which cannot be tested on the development network); (2) `docker compose up --wait` fails on the runner's Compose ("container ekmmock-dev-seed exited (0)": the one-shot containers exit, and that Compose version treats this as an error with `--wait`, while Compose 5.6.1 locally did not).
  Fix: no `--wait`; `make compose-up` / `scripts\dev.ps1 compose-up` run `up -d --build`, then `docker wait ekmmock-dev-seed` (must be 0) and poll the server's health. (3) `ArchitectureTests.Production_ComposesTheRealMtlsAuthorizer_AndEkmListenerPorts` (an M3-era test) built the production composition with the default `Data:Path=/data`, which the unprivileged runner user cannot create (on the developer's Windows machine it silently created `F:\data`); it passed in a root container. The test now uses a temporary data folder.
  The Linux CI simulation is therefore run as a **non-root user** too. The browser job (Chromium installed with `--with-deps`) passed.
  (4) The Windows job failed one console test (`PlaygroundPageViaEkmTests.ARoundTripViaTheEkmEndpoint...`: a bUnit wait of 5 s timed out on the shared runner's first mutual-TLS handshake). The tests' `Patience` constant is now 20 s (a passing test returns as soon as the condition holds; only a broken one takes longer). Everything else passed on Windows (2174 of 2175).
- **Second run (42713960603, commit 42b0322): all four jobs green.** Linux 2175 tests (2171 passed, 0 failed, 4 skipped: the Windows-only ones) and a clean vulnerability scan; Windows 2175 tests (2171 passed, 0 failed, 4 skipped: the Linux cipher tests); browser tests 13 of 13; image job: hardening checks, **conformance 49 checks: 44 PASS, 0 FAIL, 5 SKIP**, and the restart test 14.13 PASS across `docker compose restart`. Wall time: Windows about 5.5 minutes, Linux about 4.5, image about 1.5 (cold runner, nuget.org).
- **Third run (a docs-only commit, same code as the second) failed two timing-sensitive tests on the Windows runner**: `KeyStoreTests.UsageCounters_AreFlushedLazilyByTheTimer` (a 50 ms timer, 10 s limit) and `FaultInjectionTests.AClientThatGivesUpDuringTheDelay...` (the inspector had not stored the aborted exchange within 10 s): the four test assemblies run in parallel on a two-core runner and starve each other (they had passed in the previous run). Mitigations, none of which weakens an assertion: both waits are 30 s (a passing run returns at once), and the CI test steps run **one assembly at a time** (`--max-parallel-test-modules 1`; locally 3.6 minutes for the whole solution). Lesson recorded in open question 68: on shared hardware these tests are the first to suspect, rerun before suspecting the code.
- **Dependabot side effect**: the first push made Dependabot open three PRs. Two were the **Fluent UI Blazor 4.14.5 to 5.0.1** major bump (breaking, deliberately not taken: open question 37): closed with a comment, and `dependabot.yml` now ignores semver-major updates of `Microsoft.FluentUI.AspNetCore.Components*`. PR #1 (xunit.v3 4.0.3, bunit 2.14.0, minor/patch group) is left open for the owner to review.

### M9 (1/2): Tests and results
- **Totals** (Windows, `dotnet test EkmMock.sln`, final code, including the browser tests): **2188 tests, 2184 passed, 0 failed, 4 skipped** (the four Windows-irrelevant `CipherPolicyTests.Linux_*`; was 2030). Per project: Server 1301, Cli 280, Console and Crypto the rest.
  New test classes: `HealthCommandTests` (33, Cli), `ConsoleContainerPublishTests` (100), `DataProtectionKeyFolderTests` (6), `DeploymentFilesTests` (18) (Server), a banner test in `ShellTests` (Console).
- **Linux**: the Server project in the SDK container (`tests/run-server-tests-linux.ps1`): 1301 tests, 0 failed, 4 skipped (the Windows-only `WindowsKeyContainerTests`). A **simulation of the CI Linux job** (clean `sdk:10.0-noble` container, `dotnet build -c Release -warnaserror`, `dotnet test --solution ... --filter-not-trait "Category=Browser" --report-xunit-trx`, restoring through the corporate mirror via `RestoreSources`): **2175 tests, 2171 passed, 0 failed, 4 skipped** (all four projects, including the Cli and Console tests, which had never run on Linux before). The browser tests were not run on Linux.
- **Flake runs**: the Server and Cli projects four times in a row (one full-solution run and three project runs) on the final code: **all 8 project runs green, no flake** (Server 1301/1297 passed/4 skipped each time, Cli 280/280 each time).
- `dotnet build EkmMock.sln -warnaserror`: 0 warnings, 0 errors. `dotnet list package --vulnerable --include-transitive`: no vulnerable package in any project.

## M9 (2/2): Azure Bicep (VM and ACI), end-to-end script, README, RUNBOOK and RESULTS

Scope of this half: `deploy/azure/` (`vm.bicep`, `cloud-init.yaml`, `vm-setup.sh`, `aci.bicep`, example parameter files, `bicepconfig.json`, `e2e.sh`, a README), the root `README.md`, `docs/RUNBOOK.md`, `docs/RESULTS.md`, the consolidation of this file and of `OPEN-QUESTIONS.md` (status table, items 70 to 76), a CI job and tests.
**Nothing was deployed and no Azure resource was created.** The templates were built, linted and formatted offline; Azure itself was never contacted except for reading the Microsoft Learn pages and running `az ... --help`.

### Why two templates, and which is recommended
The spec (11.3) asks for a VM (recommended) and ACI (alternative). The VM is recommended for a decisive reason: the console. On a VM it stays on the loopback (`ssh -L`) and needs no authentication system, and the container runs with the full spec 5.5 hardening. ACI cannot tunnel to a loopback port, so the console needs **Entra ID on a second public port**, ACI has no read-only root file system, no capability drop and no NSG on the group's public IP, and it cannot be known whether the non-root user can bind 443 there.
So `aci.bicep` states these limits in its header and in the README and has a `runAsRoot` parameter (default `false`) as a last resort, instead of pretending ACI is equivalent. Both templates carry the comment that no TLS-terminating front end is used or supported, and a static test (`AzureDeploymentFilesTests`) rejects any front-end resource type.

### `vm.bicep`
- **Region**: a `location` parameter (default the resource group's). The reason is documented in the file and the README: the 250 ms budget includes the network distance between the Managed HSM pool and the proxy.
- **Resources and API versions**: NSG, VNet + subnet (child resource, `parent:`), Standard static public IP with `dnsSettings.domainNameLabel`, NIC, VM (Ubuntu 24.04 LTS `Canonical:ubuntu-24_04-lts:server`, Gen2). The versions are the newest the Bicep 0.42.1 type library has (network 2025-05-01, compute 2025-04-01); `bicepconfig.json` turns on `use-recent-api-versions` and the secret rules as warnings/errors. Symbolic references only, `uniqueString` names with a prefix (`namePrefix`, 3 to 12 characters), lowerCamelCase, `@description` on every parameter and output, validation with `@minLength/@maxLength/@minValue`, `@allowed` only for `imageSource` and the disk type.
- **NSG**: `allow-ekm-https-443` from `Internet`, `allow-ssh-from-operator` from `allowedSshSourceAddress`, an explicit `deny-all-other-inbound` (the default rules would deny too; the explicit one documents the intent and a test pins the three port values `443`, `22`, `*`). Port 8080 is not opened anywhere. **`allowedSshSourceAddress` is required and has no default. (Superseded, security review L7: the denylist of `*`, `0.0.0.0/0`, `Internet`, `Any` ... was replaced by a positive validation, see the follow-up section.)** Bicep has no deployment-time assert and no regex decorator, so the guard is `substring(value, 0, acceptable ? length(value) : 100000)`: for a value that is not acceptable ARM refuses the template ("The index and length parameters must refer to a location within the string"), otherwise it returns the value unchanged.
  (First attempt: an unconditional out-of-range `substring` is a compile error, `BCP327`, because Bicep evaluates literals; the ternary on a parameter is not constant-folded. Verified with `bicep console`.)
- **VM**: SSH key only (`disablePasswordAuthentication: true`, no admin password), `deleteOption: 'Delete'` on the OS disk, NIC and public IP (so that deleting the VM leaves nothing billed behind; the resource group delete removes the rest), managed OS disk with platform-managed key encryption (the Azure default; the parameter description says so), **encryption at host as an opt-in parameter** (`enableEncryptionAtHost`, default false, because it needs a subscription feature registration), **managed boot diagnostics** (`bootDiagnostics.enabled` without a storage account), tags (`application`, `purpose` plus a `tags` parameter). **Trusted launch is not configured**: whether `Standard_B2s` supports it could not be verified offline.
  **No auto-shutdown**: it would take the EKM endpoint offline (Managed HSM sees a failing proxy); the cost note and the `az vm auto-shutdown` command are in the README and the header.
- **Outputs** (no secrets, a test scans them): `fqdn`, `publicIpAddress`, `vmName`, `sshCommand`, `consoleTunnelCommand`, `fetchRootCaCommand`, `bootstrapLogCommand`.
- **Fault injection** defaulted to **on** in the VM (the spec 15 scenarios need it) and to off in ACI. **Superseded (security review L6): the VM default is now `false` too**; set `enableFaultInjection = true` for the scenarios.

### cloud-init, the setup script and the image
- **Design**: `cloud-init.yaml` only writes files (`write_files`, every one `encoding: b64`) and runs one command; the logic is in `vm-setup.sh`, a normal shell file that **shellcheck can check**, that can be sourced by tests (`main` runs only when executed) and that doubles as the on-VM tool (`bootstrap`, `run`, `upgrade`, `status`). Bicep replaces `@@TOKEN@@` placeholders with **base64 values** (`reduce()` over a token array) so that **no parameter can inject YAML or shell**: the script reads each value back from a small file with `cat`; a test checks that the tokens in the YAML and in the Bicep are the same set and that each is replaced by `base64(...)`.
  `bool` values are written as `'true'`/`'false'` explicitly (ARM's `string(true)` is `True`, which a case-sensitive shell comparison would miss: found while rendering the document).
- **Docker**: from Docker's official apt repository, **the signing key's primary fingerprint (`9DC858229FC7DD38854AE2D88D81803C0EBFCD88`) is checked and the install is refused on a mismatch**; the value was verified by downloading the live key and reading it with `gpg`. No version pin (Docker's repository carries the current release); the repository key is the verification. `docker.io` from Ubuntu's archive was rejected as an alternative because the spec asks for Docker's own repository.
- **Image**: no image is published, so `imageSource` is `build` (default: clone `repoUrl` at `repoRef`, `docker build -f deploy/docker/Dockerfile`, with `REVISION` set to the commit; the URL must be `https://`, the ref must not start with `-`; **pin `repoRef` to a tag or a SHA for reproducibility**, the default `main` moves; **superseded (security review L6): `repoRef` now defaults to the placeholder `<REPLACE-WITH-TAG-OR-SHA>`, which fails a `build` deployment**) or `pull` (your own registry, optional `registryUsername` and secure `registryPassword`, a login that is undone after the pull, no `latest`).
- **Container**: `docker run`, not compose, because the VM needs one container and a script that recreates it. The flags are those of `compose.yaml` (`--read-only`, tmpfs `/tmp`, `--cap-drop ALL`, `no-new-privileges`, no `--user`, `--restart unless-stopped`, the image's health check), `--publish 443:8443` and **`--publish 127.0.0.1:8080:8080`** with `EKMMOCK_CONSOLE_CONTAINER_PUBLISH=true` and `Endpoints__Console__Url=https://0.0.0.0:8080`, the one documented opt-in (a test pins that no other publish form of 8080 exists in the script). The master key is a read-only bind-mounted file (`EKMMOCK_MASTER_KEY_FILE`).
- **The master key on the VM**: written from the `@secure()` parameter by cloud-init to `/opt/ekmmock/secrets/master.key` (mode 0400, root-only directory), `chown`ed to uid 1654 by the script. **Decided not to scrub** the root-only copies of the custom data that cloud-init and the Azure agent keep: deleting platform files could break the agent, and root on the VM (or Azure RBAC rights to run commands on it) can read the key file anyway. The residual copy is documented (OPEN-QUESTIONS 72, RUNBOOK section 3, template header).
- **TLS certificate and the SAN flow**: the FQDN is computed in the template before the public IP exists (`<dnsLabel>.<location>.cloudapp.azure.com`, public clouds only), written to `/opt/ekmmock/config/fqdn`, and on first boot the image's own CLI (`docker run --entrypoint ekmmock`, same hardening) creates a test root CA and a server certificate with **SAN = the FQDN plus `localhost` and `127.0.0.1`** (the extra SANs let the console, reached through the tunnel on the same certificate, verify against `root-ca.pem`; Managed HSM only checks the host it was given). The server certificate and key are copied to `/data/tls` (the server persists an uploaded certificate over the files it started with, so `pki/` keeps the CLI's originals), the public `root-ca.pem` is copied there too (the console's Certificates page serves it from `/data/tls`, only while it issued the served certificate).
  **(Superseded, security review L5: the CA key is now in `/opt/ekmmock/pki-private/root-ca.key`, root-owned and not mounted into the container; see the follow-up section.)** The CA's private key stayed in `/data/pki/root-ca.key` (mode 0600, container user) and never leaves the VM: it allows re-issuing under the same root, which is what keeps the root registered with Managed HSM valid (resolving open question 41 for the VM flow); the README says to delete it if that ability is unwanted. Bring-your-own certificate: `generateTestCertificate=false`, copy the files, run `ekmmock-vm.sh run`.
- Tests: the rendering of the document was checked with a script (the YAML parses, the files decode, the permissions are as intended); `registry_host` and `cfg` were run in a shell; shellcheck is clean at `style` severity.

### `aci.bicep`
- EKM endpoint on **443 inside the container** (`var ekmPort = 443`, `Endpoints__Ekm__Url=https://0.0.0.0:443`), the console on a parameter `consolePort` (default **8443**, 1024 or above so that it cannot collide with 443) with `Console__Auth=EntraId` and the tenant, client, object ids and group as parameters; `EKMMOCK_CONSOLE_CONTAINER_PUBLISH` is never set (it is refused with `EntraId` anyway) and a test pins that.
- **Secrets**: the master key and the Entra client secret are `secureValue` environment variables, the TLS private key is a secure parameter delivered in a read-only **secret volume**, the registry credentials a secure object; none is an output. The Azure Files key is read with `listKeys()` inside the template (an SMB mount needs it) and is never an output (a test rejects `listKeys` and `storageAccountKey` in outputs).
- **Certificate**: the FQDN `<dnsNameLabel>.<location>.azurecontainer.io` must be known before the deployment (it is the SAN), so the DNS label scope is the **legacy/unsecure** one: the secure scopes (`autoGeneratedDomainNameLabelScope`) insert a hash that cannot be known in advance; the subdomain-takeover trade-off is documented in the file. (A first draft used `dnsNameLabelReusePolicy`, which the type library does not have: the compiler said so.)
- **`runAsRoot`** (default `false`): sets `securityContext.runAsUser/runAsGroup` to 0. The Bicep type accepts it; whether ACI honours it outside confidential containers is unknown (OPEN-QUESTIONS 73). The fallbacks are listed in order: the VM, `runAsRoot`, a derived image with `USER 0`.
- Storage account: Standard_LRS, TLS 1.2 minimum, no public blob access, shared key access **on** (the mount needs it), a 5 GiB SMB share. No network policy beyond what ACI allows (a container group's public IP cannot be behind an NSG).

### Secret handling in the infrastructure code
`@secure()` + `@minLength(44)/@maxLength(44)` on the master key (a 32-byte base64 value), secrets never in outputs, never in parameter files, never on the command line: the example `.bicepparam` files read them with `readEnvironmentVariable()` (and `loadTextContent(readEnvironmentVariable(...))` for the ACI certificate files), `az.getSecret()` is documented as the Key Vault alternative. The examples use `<REPLACE-...>` placeholders; because `bicep build-params` **validates the length decorators**, the GUID placeholders are exactly 36 characters long
(the check found that the first placeholders were too long and too short). `.gitignore` ignores `deploy/azure/*.bicepparam` except `*.example.bicepparam`, `*.parameters.json`, transient ARM JSON (`deploy/azure/*.json` except `bicepconfig.json`), `e2e-work/`, `root-ca.pem` and `mhsm-client.json`; `.gitattributes` forces LF for `deploy/azure/**`. A scan test (`AzureDeploymentFilesTests`) rejects private-key headers, 32-byte base64 values, long base64 blobs, subscription paths, real-looking GUIDs (only the all-zero placeholder and the spec's two request-context examples) and literal `cloudapp.azure.com` / `azurecontainer.io` host names in `deploy/azure`, the README, RUNBOOK and RESULTS.
**Line endings**: files created by the tooling here were CRLF in some cases; a CRLF `#cloud-config` header would not be detected, so every file in `deploy/azure` is LF and a test enforces it.

### `e2e.sh` (spec 15)
- **Structure**: `set -euo pipefail`, bash 5 (`EPOCHREALTIME`), `--help`, global options mirrored by environment variables, subcommands in the spec's order (`prereqs`, `trust`, `connect`, `keys`, `roundtrip`, `all`) plus one per scenario (`baseline`, `sweep`, `key-disable`, `key-destroy`, `offline`, `observe`) and `cleanup`. **`--dry-run`** prints every command with a leading `+` (quoted so it can be pasted), executes nothing and writes nothing (not even the work folder); it was run for every subcommand.
- **Only commands that exist**: the `az keyvault ekm-connection` group and the flags used (`create --hsm-name --host --server-ca-certificate [--path-prefix]`, `update`, `check`, `show`, `delete`, `certificate show`), `az keyvault key create --external-key-id`, `az rest --resource https://managedhsm.azure.net ... api-version=7.5` were taken from `--help` of the installed CLI (2.92.0) and Learn; differences are in OPEN-QUESTIONS 71. `connect` uses `update` when `ekm-connection show` finds a connection (a pool has one), `keys` skips an existing reference (the external id is immutable per version, a repeat would create a new version).
- **The DEK**: a random 32 bytes from `openssl rand`, base64url without padding (the encoding the API wants) into a `0600` request body file that is **deleted on exit** (a trap), compared after unwrap by bytes; the output shows only the length and the SHA-256 fingerprint prefix of 12 hex characters, **the same fingerprint the console shows**, so the two sides can be matched; a test pins that no `say`/`echo` line mentions the DEK variables.
- **Console access**: `ekmmock` through the SSH tunnel (`--console https://127.0.0.1:8080`, trusting `root-ca.pem`, whose SAN includes `127.0.0.1`, or `--insecure-console` which the CLI itself restricts to loopback); fault rules for delays the CLI presets do not offer (50, 150, 240, 300 ms) are created with `curl` against `POST /api/console/faults` (the headers, so a bearer token, are never echoed); a trap removes every rule the script created.
  A path prefix creates a namespace named after it (`/contoso/prod` becomes `contoso-prod`) and trusts the Managed HSM identity there. For ACI, `EKMMOCK_CONSOLE_ARGS` and `EKMMOCK_CONSOLE_TOKEN` pass the Entra options.
- **Scenarios**: `baseline` (1,000 sequential `az rest` calls, each starts an `az` process, so the client time is not proxy latency; the EkmMock side is saved from `/api/console/dashboard` and `/api/console/export`, the Azure-side KQL is printed or run when `LAW_ID` is set), `sweep` (a rule per delay, `SWEEP_CALLS` unwraps each, the exchanges saved), `key-disable`, `key-destroy` (**a throw-away key, never the real ones**), `offline` (HSM offline, then blackhole with `timeout 300`), `observe` (the inspector export and a grep summary of algorithm, byte sizes, HTTP version, ALPN, padding), `cleanup` (needs `--yes`; deletes the key references, the connection, the EkmMock keys; prints the group delete command rather than guessing the resource group).
  Every scenario writes a snippet to `e2e-work/results/<scenario>.md`.
- **Verified here**: `bash -n`, shellcheck (`koalaman/shellcheck:stable`, `-x -S style`, clean), `--dry-run` of all subcommands, and the **local logic against a test double of `az`** (an identity wrap/unwrap): two PASS lines, the failure path (a changed unwrap result: FAIL, exit 1), no plaintext files left, nothing secret-looking in the work folder. **Not verified**: every call to Azure and to a real console (see OPEN-QUESTIONS 74).

### Documentation
- `README.md` (root): what and why with the disclaimer, a Mermaid architecture diagram, features, quick start, the configuration reference, security notes (trust model, the limits of managed memory (spec 5.2), the container-publish opt-in and its residual risk, platform notes), CLI, deployment options, testing, the benchmark baseline **read from `docs/benchmarks/*.json`** with machine information and the stall and open-loop caveats, limitations and the licence note (**no licence file exists; none was invented**).
- `docs/RUNBOOK.md` (spec 9): operation, master key custody, certificate renewal, trust after a rotation (CN and root CA), the handshake-failure reason table (the labels of `HandshakeFailureReasons`), the **KQL quoted from the Learn quickstart and logging article** and the repository's `KqlSnippets` output, correlation of `correlation_id`, diagnostic settings (AuditEvent) and the `EkmProxyAvailability` metric, latency triage, the fault playbook, Prometheus, VM/container/ACI operations, a troubleshooting matrix adapted from Learn, the clean-up order and destructive-action warnings.
- `docs/RESULTS.md`: a **measured** part (totals, conformance, container verification, CI, benchmarks, offline validation), the **spec 14 matrix** (27 rows) with test names that a test (`DocumentationTests`) checks against the sources, and the **Azure template** where every `Measured` cell says `NOT YET MEASURED` (also enforced by a test) and `Expected` is labelled as an expectation. `DocumentationTests` also checks every relative link and anchor of the documentation.
- `docs/OPEN-QUESTIONS.md`: a status table at the top (open / answered / not verifiable offline) and items 70 to 76. This file: the table of contents at the top.

### CI
A fifth job, `azure-templates` (`ubuntu-latest`, same hardening as the others: SHA-pinned checkout without persisted credentials, `contents: read`, a timeout, no `${{ }}` in the script): `az bicep install`, `az bicep build` and `az bicep lint` of both templates **failing on any diagnostic line**, `bicep build-params` of the example files with dummy values, `bash -n` and shellcheck of both scripts, and `e2e.sh --dry-run` of every subcommand. It needs no Azure login. `DeploymentFilesTests` now expects five jobs.
The job installs the latest Bicep, so a new Bicep release can add diagnostics (OPEN-QUESTIONS 76).
**What the first run of this half found**: the new `azure-templates` job and the Windows, browser and image jobs were green, but the Linux job failed `CipherPolicyTests.Linux_AClientOfferingOnlyAes128_NegotiatesAes128_AndTheEventSaysSo` (an existing M3 test, unrelated to the new files): it took "the next `HandshakeSucceeded` event after a mark" and got the event of the **previous** test's AES-256 connection, which that test never waited for and which the server published late on a slow runner (the sequence number is assigned at publish time).
Fix: the test now selects the event by the client's local port (`RemoteEndPoint` ends with it). Verified in the Linux container (`tests/run-server-tests-linux.ps1`: the six `CipherPolicyTests` pass; the new test classes pass on Linux too).

### M9 (2/2): Not covered / deliberately skipped
- No deployment, no `what-if`/`validate` (they need a subscription and an existing resource group: not run, not faked); no ACI, VM or Managed HSM run; no Private Link IaC (spec 11.4); no managed identity, Key Vault or Log Analytics resources in the templates (the diagnostic setting of the Managed HSM is the user's, documented in the RUNBOOK); no trusted launch; no auto-shutdown; no master-key rotation (documented as unsupported).
- The `e2e.sh` role check and the output shapes it assumes are best effort; the Windows (PowerShell) twin of the script was not written (bash on Linux, macOS with bash 5, or WSL).

### M9 (2/2): Tests and results

- **Totals** (Windows, `dotnet test EkmMock.sln` including the browser tests, 9 November 2026): **2206 tests, 2202 passed, 0 failed, 4 skipped** (the four `CipherPolicyTests.Linux_*`; was 2188). Per project: Crypto 308, Server 1319, Cli 280, Console 299. 18 new tests: `AzureDeploymentFilesTests` (no committed secrets or environment values; secrets are `@secure()` and never outputs; the master key parameter is exactly 44 characters; no TLS-terminating front end; the NSG opens only 443, the operator's SSH and nothing for 8080; the guard values of the SSH source;
  the VM script publishes the console on `127.0.0.1` only with the hardening flags and the verified Docker key fingerprint; the cloud-init tokens equal the Bicep tokens and every file is `encoding: b64`; the ACI template listens on 443 in the container, uses EntraId and secure values and defaults to non-root; no `:latest`; LF-only files; the `e2e.sh` rules) and `DocumentationTests` (every relative link and anchor of the documentation resolves; the RESULTS matrix names only existing tests and has all 27 rows with an allowed status; no Azure cell of RESULTS says anything but `NOT YET MEASURED`).
  Mutation check: a broken link, a broken anchor and a non-existent test name in RESULTS each made `DocumentationTests` fail.
- `dotnet build EkmMock.sln -warnaserror`: 0 warnings. `dotnet list package --vulnerable --include-transitive`: clean for all 9 projects.
- Offline validation of the Azure artefacts: see [RESULTS](RESULTS.md) section 1.6 (Bicep build/lint/format and `build-params`, `bash -n`, shellcheck, `e2e.sh --dry-run` of every subcommand, the `az` test double, the cloud-init rendering, the live Docker key fingerprint).
- **Not verified**: any deployment, the VM boot flow, ACI, `e2e.sh` against a real Managed HSM, `az deployment group validate/what-if` (OPEN-QUESTIONS 72 to 74).

## Security review follow-up

A read-only security review of the finished M1 to M9 code found no critical or high issues and the findings below. Every one is either fixed with a test that proves the fix, or documented here as a decision with the reason. Findings are named as in the review (M = medium, L = low, I = info).

### M1: the identity cross-check fails closed and binds the request to the handshake's validation
- **What it checked before (`MtlsCallerAuthorizer`):** the certificate on `context.Connection.ClientCertificate` against the certificate the post-TLS middleware had recorded **from the same TLS feature**, and only when a registry entry existed and `HandshakeCompleted` was true. A missing entry or an unfinished handshake **skipped** the check (fail open), and both sides of the comparison came from one source, so it could only catch a bug in our own copy.
- **What it binds now:**
  1. `HandshakeVerdict` has `LeafThumbprintSha256`: the SHA-256 thumbprint of the leaf **the validation callback actually saw** (`ClientCertificateValidator.Validate`, the code Kestrel's `SslStream` calls during the handshake, stored on the connection through the `AsyncLocal` the capture middleware sets).
  2. On a TLS request, no registry entry for `context.Connection.Id`, or `HandshakeCompleted == false`, is a **failure** (`AuthFailure.ConnectionStateMissing`, wire answer: the usual `401 Unauthenticated`). A request without a certificate still takes the no-certificate 401 path on a known connection.
  3. When the request carries a certificate, three things must agree: the post-handshake record (existing `ClientCertificateChanged` check), a **non-null, `Accepted`** verdict on the connection (`AuthFailure.HandshakeVerdictMissing`), and the verdict's `LeafThumbprintSha256` equal (case-insensitive) to the request certificate's SHA-256 thumbprint (`ClientCertificateChanged`).
  So a certificate that reaches a request by any route other than "the TLS stack handed it to the validation callback, which accepted it" is refused. The seams are unchanged: the in-process test host replaces `IEkmCallerAuthorizer` and `IEkmPortPolicy` through DI (no TLS feature there, so `NoTransportSecurity` is not involved); there is no production bypass flag.
- **Tests:** `MtlsCallerAuthorizerUnitTests` (a matrix over a real `ConnectionRegistry`: missing entry, incomplete handshake, unknown connection without certificate, no verdict, verdict not accepted, verdict of another leaf, verdict without thumbprint, case-insensitive comparison, all consistent, and the real validation callback recording the thumbprint) plus every existing mTLS test (77 in the `*Mtls*` classes, `AuthCaptureTests`, `InspectorMtlsTests`, console port separation) unchanged and green.
- **The intermittent Windows finding of M3 is still unexplained.** The "request without a certificate authorized as an earlier identity" failure (2 of 15 full runs on Windows during M3, never reproduced since) has **no proven root cause**; disabling TLS session resumption was the only fitting mechanism and was never shown to be the cause. This follow-up does **not** claim to fix it. It makes such an event, whatever its cause, fail closed: a certificate on a request that the handshake validation did not accept is a 401, and a request on a connection the registry does not know is a 401. If it ever recurs, the `auth_failure` in the log line and in the inspector says which of the three checks refused it. (OPEN-QUESTIONS 77.)

### M2: the inspector's memory is bounded in bytes, and unauthenticated traffic keeps only a little
- **Why the old bound was wrong:** `RingBufferSize` bounds records, not bytes, and a record is mostly attacker-controlled text. Up to 64 headers of 1024 characters (two bytes each) on each side plus two 16 KiB bodies is about 100 KB per record; 10 000 records is about 1 GB, reachable by anonymous requests (a request is captured before it is authenticated).
- **Byte cap:** `Inspector:MaxBytes` (default 128 MiB, minimum 64 KiB, startup-validated, shown on the About page). `ExchangeRecordSize.Estimate` counts every string a record holds at two bytes per character, header and masked-field overheads, a fixed 1 KiB per record and the raw bodies kept for reveal; it runs **once, when the consumer adds the record** (not on the request path). `ExchangeRingBuffer` keeps the running total and, after every add, evicts the oldest records (zeroing their raw secrets, as eviction always did) until the total is under the cap; the newest record is always kept, even when it alone is larger. The figure is an **estimate** (it ignores CLR object layout, the lazily created pretty-printed JSON of a record somebody opened in the console, and dictionary overheads), documented as such.
- **Unauthenticated records are small by construction.** `ExchangeRecordFactory` treats an exchange as unauthenticated when `exchange.Authentication` is not a success (a 401, an unroutable path, a 405, anything rejected before or without the Auth stage): request and response body **text is cut to 1 KiB** (after redaction, so masking is untouched and the cut can only remove content; the body is marked `Truncated`, which also hides the pretty JSON, and its real size is still reported) and headers are stored up to **4 KiB** of name plus value characters in total (`HeadersTruncated` on the request and response facts, shown in the console as "Headers truncated" and in the body heading as "truncated (only the beginning is shown)"). Authenticated exchanges keep the old shape, with a 16 KiB header budget added (the 64-header and 1024-character limits stay). An unauthenticated exchange also keeps **no raw secret** for reveal (it can never be replayed or revealed: it is not an authenticated call).
- **Channel and feed (count-bounded, worst case stated):** the queue between the request path and the consumer is count-bounded (`Inspector:ChannelCapacity`, **default lowered from 8192 to 4096**); live-feed subscriptions share the same immutable records (1000 per console). With the caps above, the documented worst case of one unauthenticated record is **about 24 KiB** (4 KiB of headers per side, 1 KiB bodies, a 2048-character target, certificate names, overheads; a test pins "below 24 KiB"), so at the defaults: ring 128 MiB + queue 4096 × 24 KiB = 96 MiB (transient, only while the consumer lags) + 24 MiB per open console for records the ring has already evicted, about 250 MiB in the very worst case; a typical `info` probe is about 3 KB. An authenticated record can reach about 100 KiB (two 16 KiB bodies and 16 KiB of headers as UTF-16), but authenticated callers are the trusted Managed HSM identities and the ring byte cap bounds what is retained.
- **Azure templates:** they did not pass any inspector setting. They do now: the VM container gets `Inspector__RingBufferSize=5000`, `Inspector__MaxBytes=67108864` (64 MiB) and `Inspector__ChannelCapacity=2048` (worst case about 64 + 48 MiB on a 4 GiB B2s); the ACI container `2000`, `33554432` (32 MiB) and `1024` (about 32 + 24 MiB on 2 GiB). Static tests pin the values.
- **Tests (`InspectorMemoryBoundTests`, 17):** eviction by bytes with exact survivors; raw secrets zeroed on a byte eviction; secrets count towards the bytes; the newest record is kept when it alone exceeds the cap; `Clear` and out-of-order inserts keep the account exact; a 5000-record deterministic flood with a 256 KiB cap never exceeds it; hostile unauthenticated requests (50 headers of 900 characters, a 15 000-character body, a 5000-character query) produce capped records through the real pipeline; an unroutable request is capped too; an authenticated exchange keeps its full body and headers; a DEK in an unauthenticated wrap request is masked and nothing raw is retained even with reveal on; a DEK **beyond** the 1 KiB cut never appears; a flood of 400 hostile requests through the real host with `Inspector:MaxBytes` at 200 KiB stays under it. The masking and leak-scan tests (`SecretMaskingTests`, `InspectorMaskingEndToEndTests`, `InspectorRevealTests`) are unchanged and green.
- **Benchmark (spec 14 test 24, p99 < 1 ms), measured on the final code** (Windows 11, .NET 10.0.14, 8 logical cores, Debug test assembly, 20 000 requests after 10 000 warm-up; `inspector-benchmark.txt`): capture overhead inside the middleware p50 / p90 / **p99** = 16.4 / 19.0 / **28.8 µs** (masked, the default) and 16.6 / 19.8 / **32.3 µs** (reveal allowed); end-to-end difference with and without capture p99 +27.7 µs / +30.4 µs; 0 captures dropped. Both are far under the 1 ms threshold, which is asserted unchanged (p99 of the capture and p99 of the end-to-end difference). Earlier recorded runs (M4) gave p99 125.9 and 134.4 µs on a busier machine state; the figures differ by run, the threshold is what the test enforces. The request path gained only a boolean and a header-budget loop; the estimate runs on the consumer thread, which the benchmark does not charge to the request (by design: the capture never awaits the consumer).

### L1: connection limit and rate limited handshake-failure logging
- **Limit:** `Limits:MaxConnections` (default 1000, startup-validated, on the About page): connections open on the EKM listener (still handshaking or established) beyond it are **closed at once** by the capture middleware (`ConnectionCapture.Outer`, which sits before TLS, so a flood is stopped before any TLS work). **Deviation from the review's wording:** Kestrel's own `Limits.MaxConcurrentConnections` is *server wide*, so a flood of anonymous connections to the public EKM port would also lock the console out (and on ACI the console is public too); the per-listener counter limits only the EKM listener. It counts atomically, logs one rate-limited warning with the refusal total and exposes `RejectedConnections` and `ActiveConnections`. Tested with hand-made connections (limit reached, refusal, limit frees up, flood of 200 refusals logs 5 lines) and on a real Kestrel listener (3 held connections within a limit of 3, the 4th is closed, the console still answers).
- **Log:** the per-failed-handshake warning is rate limited by `WarningThrottle` (at most 5 lines per second per listener, plus a summary line "N further TLS handshake failure(s) were not logged one by one in the last 10 s" handed out with the next failure after 10 seconds; no timer). **Nothing is lost for diagnosis:** the `HandshakeFailed` connection event and `ekmmock_tls_handshake_failures_total` still record every failure (test: 300 failures, 5 log lines, 300 events, 300 counted, summary of 295).

### L2: Entra tenant must be a GUID, and the `tid` claim is always enforced
`Console:EntraId:TenantId` must be the 36-character GUID form (not `common`, `organizations`, `consumers`, a domain name, braces, the all-zero placeholder): the console **refuses to start** otherwise, with a message that says why. `ConsoleAccessPolicy` previously skipped the tenant check when the token had no `tid` claim; it now **requires** the claim (short or long form) to equal the configured tenant, and an unparseable configured tenant denies everybody (fail closed) instead of nobody being checked. The test authentication scheme of the test host now emits the tenant claim by default like a real Entra token (`X-Test-No-Tid` removes it); the existing validation matrix is unchanged (its tenants were GUIDs) and `ConsoleTenantEnforcementTests` adds the cases (no claim, other tenant, unreadable claim, conflicting short and long claims, non-GUID configuration, startup refusals).

### L3: audit first, then change; bounded reader; rotation
- **Audit-first (`AuditRecorder.Intend`):** the entry is written **before** the change; if it cannot be written the answer is `503 AuditUnavailable` "nothing was changed" and the change is never applied. If the change then fails, an `action.failed` entry (target of the action, detail `"<action>: <reason>"`) records the outcome and the original error is rethrown. Callers validate first (existence, confirmation text, input), so a refused request is not audited as an attempt (the existing tests that pin "a refused action is not an audited change" stay green). **Done for:** `key.destroy`, `key.enable`, `key.disable`, `key.expiry.set/clear`, `namespace.delete` (each implied `key.destroy` and the delete itself, in that order), `namespace.trust.import`, `namespace.trust.test-client`. The inspector's reveal and replay already audited first and failed closed (M4).
  **Not reordered, and why:** `key.create`/`key.import` and `namespace.create`/`namespace.update` (the engine and the namespace store validate and refuse inside the very call that applies the change: duplicate or reserved key names, the wrong-master-key guard, prefix overlaps; an entry written first would record refused requests as attempts, which the tests and the contract forbid, and replicating those rules in the console service would duplicate them); `certificate.upload/generate` (the audit detail is the thumbprint of the certificate, which exists only after it was parsed and installed); `fault.*` (the rule store validates inside `Add/Update`; the rules are in-memory test configuration); `playground.*` (a record of use, not a state change). For these the old behaviour stays: the change is applied and a failing audit write raises `AuditUnavailable` saying so ("The change was applied but is not recorded"); the error code documentation says which actions are which.
- **Bounded reader:** `FileAuditLog.ReadRecent(n)` reads backwards from the end of the newest file in 64 KiB blocks and deserialises only the lines it returns (and continues into rolled-over files when it needs more); a torn last line is skipped instead of failing the page. `AuditQuery` looks at the **newest 10 000 entries** (`AuditQuery.MaxScannedEntries`; it used to deserialise up to 100 000 per query, the whole history). Older entries remain in the files. A test damages the first half of a 3000-entry file to prove nothing there is read.
- **Rotation:** `Audit:MaxFileBytes` (default 50 MiB) and `Audit:MaxFiles` (rolled-over files kept, default 5): `audit.jsonl` is rolled to `audit.1.jsonl`, `audit.1.jsonl` to `audit.2.jsonl` and so on before an append would exceed the size; the oldest is deleted; the reader follows the rotation. Startup-validated. The audit log stays append-only through the console (no edit or delete path exists; `AdminApiAuditTests` unchanged).

### L4: owner-only audit and inspector files on Unix
`audit.jsonl` and the inspector JSONL files are created with `UnixCreateMode = UserRead | UserWrite` through one helper (`OwnerOnlyFile.Options`, not applied on Windows where the data folder's ACL governs, like the key store); the mode applies when the file is created and survives rotation (a rename). Tests: a unit assertion of the options (all platforms) and, on Unix, that the created audit, rolled-over and inspector files have mode `0600` (**skipped on Windows, run in the Linux container and in CI**).

### L5: the VM's test root CA key is no longer in the folder the container can read
`vm-setup.sh` generated the CA and left `root-ca.key` in `/opt/ekmmock/data/pki`, which is mounted into (and readable by) the container. Now the CLI runs against a private scratch folder (`mktemp`, owned by the container user for the one call; it is never given `$DATA`), the CA key is installed as `/opt/ekmmock/pki-private/root-ca.key` (**root-owned, mode 0400, never mounted**), the server certificate and key go to `data/tls` as before, and the scratch folder is shredded and removed. Re-issuing under the same root (which keeps the root registered with Managed HSM valid) is a new command, `sudo ekmmock-vm.sh reissue`; deleting the key file removes the ability (then a new root is needed). Older VMs: `run`, `upgrade` and `reissue` move the key out once (`move_ca_key_out_of_data`, which also removes the redundant `pki/server.key`). README, RUNBOOK (sections 2 and 4) and the supersede notes above are updated; static tests pin the paths, the key mode and that no `docker run` mounts `pki-private`. `bash -n` and shellcheck are clean. **Verified by simulation, not on a VM:** the script's functions were run as root in a Linux container with a stand-in `docker` that emulates the CLI calls: the CA key ends up as `pki-private/root-ca.key` (`0400`, root), nothing named `root-ca.key` exists under `data`, no scratch folder is left, the detached `docker run` mounts nothing from `pki-private` and carries the three `Inspector__*` settings, `reissue` replaces the server certificate, a legacy key in `data/pki` is moved out, and `reissue` without a CA key stops with a clear message. The real Docker, the real CLI image and a real VM were not involved (OPEN-QUESTIONS 72 stays open).

### L6: `repoRef` has no usable default, fault injection defaults to off
`repoRef` defaults to `<REPLACE-WITH-TAG-OR-SHA>`; with `imageSource = 'build'` a value starting with `<` fails the deployment (the same guard technique as the SSH source) and `build_image` refuses it too; with `pull` it is unused. `enableFaultInjection` defaults to `false` like `aci.bicep`. Example parameter file, README, RUNBOOK and `e2e.sh`'s message updated; the guard is evaluated by the real template in `SshSourceRuleTests` (below).

### L7: the SSH source is validated positively
`allowedSshSourceAddress` must be ONE IPv4 address, or an IPv4 CIDR with prefix `/16` to `/32`, or ONE IPv6 address, or an IPv6 CIDR with prefix `/48` to `/128`; anything else (service tags, `*`, `any`, host names, lists, wider ranges, leading zeros, `0.0.0.0`, `::`) fails the deployment. Implemented with Bicep string and lambda functions (octets, digits-only checks, group counts, one `::`), with `int()` only behind `if()` branches that are only evaluated for digit strings (ARM evaluates the chosen branch only). **Tested against the real template, not a mirror:** `SshSourceRuleTests` writes a throw-away `.bicepparam` and runs `bicep snapshot`, which evaluates the ARM template language locally (no Azure, no login): 50 inputs (accepted: single addresses, `/16` to `/32`, IPv6 down to `/48`, surrounding blanks; rejected: the former denylist, too wide, malformed octets and prefixes, lists, service tags, host names, `::/0`, `::`, `:::`, two `::`, over-long groups) plus the `repoRef` cases. A rejected input must fail through the rule (`sshSourceChecked`) or the parameter length limits, not for another reason; an accepted one must reach the NSG rule unchanged. The tests need the Bicep CLI (PATH or `~/.azure/bin`); without it they skip, and the CI `azure-templates` job sets `EKMMOCK_REQUIRE_BICEP=true` so that a missing CLI fails there. CI also gained a `bicep format` no-diff step. The Bicep files are `build`, `lint` (0 diagnostics) and `format` clean.

### L8: ACI storage account
`aci.bicep` already set `minimumTlsVersion: 'TLS1_2'`, `supportsHttpsTrafficOnly: true` and `allowBlobPublicAccess: false` (the review's three properties; a static test pins them). **No network deny rule was added**: ACI cannot be named in a storage firewall without a VNet and a deny would break the SMB mount. Documented instead (template header item 6, README limitation 3, OPEN-QUESTIONS 63 and 79): anyone holding the storage account key can read the `/data` share, including the **unencrypted ASP.NET Data Protection key ring**, and can therefore **forge a console session cookie** (and read the key store file, whose blobs stay encrypted under the master key). Recommendations: limit who has Contributor or Storage Account Key Operator on the account, rotate the key (`az storage account keys renew`, then redeploy), prefer the VM, or a later VNet-integrated variant with a storage service endpoint.

### L9: `e2e.sh` hygiene
The bearer token goes to `curl` on standard input (`--config -`, written by the `printf` builtin; checked for characters that are not valid in a bearer token) instead of argv; `--insecure` and `--insecure-console` are accepted only for a loopback console (`127.0.0.1`, `localhost`, `::1`) and otherwise the script tells you to pass `--console-ca`; the DEK and the request bodies that carry it live in a `mktemp -d` folder created with `umask 077` (mode 700) that is shredded and removed on exit, never in `--work-dir`. Verified: `bash -n`, shellcheck (`-S style`, clean), `--dry-run` of every subcommand, and a real (non-dry) run of `roundtrip` against a test double of `az` (two PASS lines, no secret folder left behind, no DEK or request body in the work folder) plus a test double of `curl` proving the token is absent from argv and present on stdin. Static tests pin the pieces.

### L10: the console takes uploads over 16 KiB
The server-wide Kestrel limit stays 16 KiB (the EKM endpoint needs it; `EndpointBehaviourTests` pins it). `ConsoleBodyLimitMiddleware`, first in the console branch only, raises `IHttpMaxRequestBodySizeFeature.MaxRequestBodySize` to `ConsoleAdminApi.MaxBodyBytes` (512 KiB) for console requests; the EKM branch does not touch it. A body over 512 KiB is refused by the endpoint with the same words (the chunked case is mapped from Kestrel's `BadHttpRequestException`, which used to become a generic 500). `ConsoleBodyLimitTests`, over real Kestrel on both listeners: a 100 KiB certificate upload and a 100 KiB trust import on the console reach their validation (a proper `400 InvalidRequest`, not a 500 and not Kestrel's 413), 600 KiB is refused with "too large" (a chunked client that keeps sending may see a reset instead, TCP), and a 20 000-byte EKM request still gets the ProxyError `400 InvalidRequest`. Without the middleware three of the six tests fail (checked).

### I8: private keys written by the PKI library
`IssuedCertificate.WriteFiles` (used by the tests, the console test hosts and the local tooling) now creates the key file through `SecureFile` (owner-only: Unix mode `0600`, a current-user-only ACL on Windows, applied at creation before any content is written); the helper moved from the CLI to `EkmMock.Pki` (the CLI references it from there). An existing key file is rewritten in place (so a certificate watcher never sees it missing) and, on Unix, tightened to `0600`. `PkiKeyFilePermissionsTests` (the Unix tightening case is skipped on Windows).

### CI result of the follow-up

- Run [42736629878](https://github.com/azureholic/ekmmock/actions/runs/42736629878) (commit db6d3fc, push to main): **green, all five jobs.** Linux: 2,292 tests (the 13 browser tests run in their own job), 2,288 passed, 0 failed, 4 skipped (the Windows-only CNG tests); Windows: 2,292 tests, 2,285 passed, 0 failed, 7 skipped (4 Linux-only cipher tests and the 3 Unix-mode tests); browser job 13 of 13; image build and conformance; Azure templates, including the new icep format step and SshSourceRuleTests with EKMMOCK_REQUIRE_BICEP=true (about 60 s). The two Bicep tests ran (did not skip) on both runners that have the CLI.

### Not changed (known and accepted)
The INFO items of the review are unchanged. Specifically still true: the Data Protection keys are unencrypted files on the data volume (OPEN-QUESTIONS 63, now with the ACI storage-key consequence spelled out); the root-only cloud-init copy of the master key on the VM (72); the Azure templates were never deployed.