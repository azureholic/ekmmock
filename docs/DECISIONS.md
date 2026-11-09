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
