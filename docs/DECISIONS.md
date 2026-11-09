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
  throw-away one (`SoftwareCryptoBackend.IsMasterKeyThrowAway`, logged as a warning now, a red console banner in M5) and the plain-HTTP guard
  is relaxed. `Dev:SeedSampleKeys=true` (default false, also off in the shipped `appsettings.json`) creates `aes-key-1` (AES-256) and
  `rsa-key-1` (RSA-2048) in `_default` if they do not exist (including as tombstones); they are created before the self-test, which then covers them.
- **No plain HTTP on a real port (M3 TODO):** `Endpoints:Ekm:Url` is a placeholder key in `appsettings.json` that no M2 code reads. The M2
  server configures no listener. `PlainHttpGuard` makes the host refuse to start when the `IServer` is anything but the in-process test
  server unless `--dev` is set (a plain `dotnet run` fails with an explanatory error; verified). **M3 TODO:** replace the guard with real
  Kestrel endpoints (TLS 1.3, cipher suites, mTLS) read from `Endpoints:Ekm:Url`, set `MaxRequestBodySize` so Kestrel does not answer
  with its own non-ProxyError 413 before the handler's 16 KiB check (until then the handler enforces the limit itself, and a
  `BadHttpRequestException` from the host is mapped to `400 InvalidRequest`), and re-verify chunked bodies and percent-encoded paths on real
  Kestrel with automated tests (M2 verified them manually only, see "Not covered" below).
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
  `Transfer-Encoding: chunked`: a 20 KB body gave the 400 ProxyError, a small one 200). Automated real-Kestrel tests come with M3.
- **Percent-encoded slashes:** the test host decodes `%2F` in the path, real Kestrel does not. A key name containing `%2F` is
  `400 InvalidKeyName` on real Kestrel (verified by hand) and a routing 404 in the test host; the automated test therefore leaves it out.
