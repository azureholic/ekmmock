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

