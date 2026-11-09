# SPEC: EKM Mock HSM ("EkmMock") for Azure Key Vault Managed HSM External Key Management

**Status:** Draft v0.2, for GitHub Copilot (agent mode) to implement
**Owner:** Remco Brosky
**Date:** 9 November 2026
**Changes since v0.1:** rewritten for **C# / .NET 10**. The app is now **its own software HSM** (no SoftHSM2, no external HSM behind it). Added a **web console** with a live **traffic inspector** that shows every call coming in, plus key management, a crypto playground and fault injection in the browser.

**Purpose:** One containerised app that Azure Key Vault Managed HSM can register as its EKM endpoint. To Managed HSM it looks exactly like a vendor EKM proxy + HSM. Inside, it really generates and holds keys and really performs the wrap/unwrap (encrypt/decrypt) operations. A browser console shows every request and response as it happens. Use it to test external key management end to end in a real Azure environment: connection setup, mTLS, wrap/unwrap, the 250 ms latency budget, and failure modes.

> **Simulator, not an HSM.** Keys live in software, protected at rest by a master key. There is no tamper resistance, no FIPS validation and no physical custody. That is fine for testing EKM behaviour, and it is useless for the compliance reasons EKM exists for. Never protect real data with this build.

---

## 0. Instructions for GitHub Copilot

1. Read this whole spec before writing code. Sections 4 (EKM API), 5 (security), 6 (software HSM) and 8 (inspector) are **normative**. Do not deviate from them.
2. Build in the milestone order in Section 13. Each milestone must build, pass its tests and be committed before the next one starts.
3. Where this spec says **MUST**, write a test that proves it.
4. **Secret and private key material MUST never leave the crypto engine** through any API, UI page, log, export or error message. The only plaintext that leaves is the DEK in an `unwrapkey` response, because the API contract requires it. The inspector masks it by default (Section 8.4).
5. If something here conflicts with the Microsoft Learn EKM Proxy API reference, stop and add a note to `docs/OPEN-QUESTIONS.md`. Do not guess.
6. Keep NuGet dependencies minimal and pinned (central package management, `Directory.Packages.props`). No telemetry or outbound calls.
7. Use only .NET's built-in cryptography (`System.Security.Cryptography`). Do not add third-party crypto libraries. Where .NET has no API (AES Key Wrap, Section 6.4), implement the RFC on top of the AES block primitive and prove it with the RFC test vectors.

---

## 1. Scope

### In scope
- **EKM endpoint:** HTTPS service implementing the four EKM Proxy API operations, **info, metadata, wrapkey, unwrapkey** (API version `0.1-preview`), with mTLS (TLS 1.3, client CN + root CA allow-list).
- **Software HSM engine:** generates, stores (encrypted at rest) and uses AES-256 and RSA 2048/3072/4096 keys. Performs A256KW, A256KWP, RSA-OAEP-256 and RSA-OAEP for real.
- **Web console** on a separate port:
  - **Traffic inspector:** every call into the EKM endpoint, live, with request, response, TLS and client-certificate details, and timing. Also TLS handshake failures that never become HTTP requests.
  - **Dashboard:** request rate, latency percentiles against the 250 ms budget, errors, Managed HSM health-probe heartbeat.
  - **Key management:** create, list, enable/disable, set expiry, destroy keys; show public keys and the matching `az` command.
  - **Trust and certificates:** paste the output of `az keyvault ekm-connection certificate show` to trust a Managed HSM pool; manage the server certificate.
  - **Crypto playground:** run wrap/unwrap/encrypt/decrypt by hand, either directly against the engine or as a real request through the EKM endpoint.
  - **Fault injection:** delay, errors, "HSM offline", blackhole.
  - **Audit log** of console actions.
- **CLI tool** (`ekmmock`): test PKI, conformance tests and load test acting as a fake Managed HSM, and scripted key management.
- Docker image, docker-compose, and Azure deployment options (Section 11).

### Out of scope
- Production hardening, high availability, clustering, horizontal scale, key replication.
- Azure Private Link setup. The design must not prevent it (Section 11.4), but no IaC for it.
- Secure Key Release or any key export. Not supported by EKM anyway.
- Forwarding to a real HSM ("proxy mode"). Keep the `ICryptoBackend` interface (Section 6.1) so a PKCS#11 backend (for example via Pkcs11Interop) can be added later, but do not build it now.

---

## 2. Background (what the app must satisfy)

Request path: **Azure service (CMK) → Managed HSM → EkmMock (proxy + software HSM in one process)**.

- Managed HSM authorises the caller and then calls EkmMock over mTLS. EkmMock never makes Azure authorisation decisions and has no Azure identity.
- Only `wrapkey` and `unwrapkey` arrive at runtime. `info` is called at connection setup and as a health probe (about 3 calls per minute). `metadata` is called when an external key reference is created. `GetKey` reads are answered by Managed HSM itself and never reach EkmMock.
- **Every call must complete within 250 ms.** After that, Managed HSM times out and returns an error to the Azure service.
- The EKM endpoint must be reachable on **TCP 443**. Non-standard ports are not supported.
- Managed HSM source IPs are not static. **Client-certificate validation is the only access control.** Do not build IP allow-listing for the EKM endpoint.
- Microsoft rotates the Managed HSM client certificate on a schedule. Trust is by subject CN + root CA, never by fingerprint.

Reference docs (Microsoft Learn): EKM overview, EKM architecture, EKM Proxy API reference, Configure networking and mTLS, Quickstart (Azure CLI).

---

## 3. Technology choices

| Area | Choice | Notes |
|---|---|---|
| Runtime | **.NET 10 (LTS)**, C# latest | Linux containers only |
| Host | ASP.NET Core, **Kestrel**, Minimal APIs | Two Kestrel endpoints (Section 7) |
| JSON | `System.Text.Json` with source generation, `JsonNamingPolicy.SnakeCaseLower` | |
| Base64url | `System.Buffers.Text.Base64Url` | Must accept padded and unpadded input (test it) |
| Crypto | `System.Security.Cryptography` only (`Aes`, `RSA`, `AesGcm`, `RandomNumberGenerator`, `CryptographicOperations`) | AES-KW/KWP implemented per RFC (6.4) |
| Web console | **Blazor Web App, Interactive Server render mode** (live updates over SignalR) | UI components: Microsoft Fluent UI Blazor (`Microsoft.FluentUI.AspNetCore.Components`) or the default Bootstrap template. Copilot picks one and records it in `docs/DECISIONS.md` |
| Charts | Small SVG components written in Razor | No chart library needed |
| Console auth | Microsoft.Identity.Web (Entra ID, OIDC) or loopback-only (Section 5.4) | |
| Logging | `ILogger` with JSON console formatter | |
| Metrics | `System.Diagnostics.Metrics`, exposed in Prometheus format on the console port | Pick OpenTelemetry Prometheus exporter or prometheus-net, record in DECISIONS |
| CLI | `System.CommandLine` | |
| Tests | xUnit + Shouldly (avoid FluentAssertions v8+ because of its commercial licence) | |
| Container | `mcr.microsoft.com/dotnet/aspnet:10.0` (Debian/Ubuntu base with OpenSSL), non-root `$APP_UID` | Needs OpenSSL for TLS 1.3 cipher-suite control |

TLS note: on Linux, Kestrel lets you set the TLS 1.3 suites explicitly through `CipherSuitesPolicy`. Restrict them to `TLS_AES_256_GCM_SHA384` and `TLS_AES_128_GCM_SHA256`, the two the API reference requires.

---

## 4. EKM API contract (normative)

### 4.1 Transport
- HTTPS only. HTTP/1.1 **MUST** work. HTTP/2 may be negotiated via ALPN. **TLS 1.3 only.**
- Request and response `Content-Type: application/json`. Reject other request content types with `400`.
- All endpoints are **POST**. Other methods return `405` with a ProxyError body.
- Max request body: 16 KiB (`MaxRequestBodySize` on the EKM endpoint). Larger returns `400`.

### 4.2 URI format

```
https://{server}/[path-prefix]/info?api-version=0.1-preview
https://{server}/[path-prefix]/{key-name}/metadata?api-version=0.1-preview
https://{server}/[path-prefix]/{key-name}/wrapkey?api-version=0.1-preview
https://{server}/[path-prefix]/{key-name}/unwrapkey?api-version=0.1-preview
```

- `path-prefix` is optional. It may contain several segments (for example `/contoso/prod`). Max 64 characters, `[A-Za-z0-9/-]` only. Validate at startup and when changed in the console.
- Support **several prefixes**, each mapped to its own **namespace** of keys and its own client trust (Section 6.3). This mirrors "one proxy, many Managed HSM pools".
- Routing: do not use template routes for the prefix. Match the longest configured prefix against the path, then parse the remaining segments (`info` or `{key}/{op}`). An unknown prefix returns `404 NotFound`.
- `key-name` (external key identifier) **MUST** match `^[A-Za-z0-9-]{1,64}$`, otherwise `400 InvalidKeyName`.
- `api-version` query parameter is **required**. Supported: `0.1-preview`. Missing or unsupported returns `400 UnsupportedApiVersion`.
- Tolerate a trailing slash. Segments are case-sensitive.

### 4.3 Common request body

```json
{
  "request_context": {
    "request_id": "6476b291-7c15-4d0b-aef9-03688390cb8e",
    "correlation_id": "aa9a3cb4-82b4-11f0-afc6-5ffd3bdade85",
    "pool_name": "mhsm-pool-name"
  }
}
```

- `request_context` is required. `request_id` is optional. Missing `request_context` returns `400 InvalidRequest`.
- Ignore unknown JSON fields (forward compatibility).
- All three fields are captured by the inspector and the logs (Section 8).

### 4.4 Error body

```json
{ "code": "KeyDisabled", "message": "Operation WrapKey is not allowed on a disabled key" }
```

| Status | When | Example `code` values |
|---|---|---|
| 400 | Invalid parameter, bad base64url, wrong length, unsupported algorithm, algorithm not valid for key type, bad JSON, bad api-version, failed unwrap | `InvalidRequest`, `InvalidKeyName`, `UnsupportedApiVersion`, `UnsupportedAlgorithm`, `InvalidCiphertext` |
| 401 | No client certificate, CN or CA not allowed for this namespace | `Unauthenticated` |
| 403 | Key disabled, key expired, operation not allowed | `KeyDisabled`, `KeyExpired`, `OperationNotAllowed` |
| 404 | Key not found in the namespace (including destroyed keys) | `KeyNotFound` |
| 429 | Concurrency limit or internal deadline reached, or fault-injected | `TooManyRequests` |
| 5xx | Engine unavailable ("HSM offline" fault), key store not loaded, unexpected error | `HsmUnavailable`, `InternalError` |

`message` **MUST NOT** contain key material, exception details or stack traces. A failed unwrap (wrong key, tampered input, integrity check failure) **MUST** return `400 InvalidCiphertext`, not `500`. Map engine exceptions to statuses in one place.

### 4.5 Encoding rules
- Every binary value (`value`, `n`, `e`) is **base64url (RFC 7515) of the raw unsigned big-endian bytes**. Output **without padding**.
- Input: accept padded and unpadded base64url. Reject standard base64 characters (`+`, `/`) with `400`.
- RSA `n` and `e`: minimal big-endian form, no leading zero byte (`RSAParameters` gives big-endian; strip any leading 0x00). Exponent 65537 is `AQAB`.

### 4.6 `POST /[prefix]/info`

Response `200`:

```json
{
  "api_version": "0.1-preview",
  "proxy_vendor": "Remco Test",
  "proxy_name": "EkmMock v0.2.0",
  "ekm_vendor": "EkmMock",
  "ekm_product": "EkmMock Software HSM v0.2.0"
}
```

- Values are configurable. `api_version` defaults to `0.1-preview`. The Learn examples show `"1.0"`; see open questions.
- If the engine is unavailable (key store not loaded, or the "HSM offline" fault is on), return `503 HsmUnavailable` so the Managed HSM health probe sees the real state.
- p99 under 5 ms locally.

### 4.7 `POST /[prefix]/{key-name}/metadata`

AES: `{ "key_type": "oct", "key_size": 256, "key_ops": ["wrapKey", "unwrapKey"] }`
RSA: `{ "key_type": "RSA", "key_size": 2048, "key_ops": ["wrapKey", "unwrapKey"], "n": "<base64url>", "e": "AQAB" }`

- Supported: `oct` 256; `RSA` 2048, 3072, 4096. `key_ops` **MUST** be exactly `["wrapKey", "unwrapKey"]`.
- A disabled key still returns metadata (`200`). Only wrap/unwrap are blocked.

### 4.8 `POST /[prefix]/{key-name}/wrapkey`
Request `{ "request_context": {…}, "alg": "A256KWP", "value": "<base64url DEK>" }` → `200 { "value": "<base64url wrapped DEK>" }`

### 4.9 `POST /[prefix]/{key-name}/unwrapkey`
Request `{ "request_context": {…}, "alg": "A256KWP", "value": "<base64url wrapped DEK>" }` → `200 { "value": "<base64url DEK>" }`

### 4.10 Algorithms

| Key type | `alg` | Implementation | Input rules (wrap) |
|---|---|---|---|
| oct | `A256KW` | RFC 3394 AES Key Wrap (Section 6.4) | DEK ≥ 16 bytes and a multiple of 8 |
| oct | `A256KWP` | RFC 5649 AES Key Wrap with Padding (Section 6.4) | DEK 1 to 4096 bytes |
| RSA | `RSA-OAEP-256` | `RSA.Encrypt/Decrypt` with `RSAEncryptionPadding.OaepSHA256` (SHA-256, MGF1-SHA-256, empty label) | DEK ≤ k − 66 bytes |
| RSA | `RSA-OAEP` | `RSAEncryptionPadding.OaepSHA1` | DEK ≤ k − 42 bytes |

- Algorithm/key-type mismatch returns `400 UnsupportedAlgorithm`.
- Unwrap input length: AES-KW/KWP a multiple of 8 and ≥ 16 (KWP) or ≥ 24 (KW); RSA exactly k bytes. Otherwise `400 InvalidCiphertext`.

---

## 5. Security (normative)

### 5.1 mTLS on the EKM endpoint
Configure through `HttpsConnectionAdapterOptions`:
- `SslProtocols = SslProtocols.Tls13`.
- `OnAuthenticate`: set `CipherSuitesPolicy` to `TLS_AES_256_GCM_SHA384` and `TLS_AES_128_GCM_SHA256`.
- `ClientCertificateMode = ClientCertificateMode.AllowCertificate`, so a request **without** a certificate reaches the middleware and gets the JSON `401` the API reference expects.
- `ClientCertificateValidation`: ignore the OS trust result. Build a chain with `X509ChainPolicy { TrustMode = X509ChainTrustMode.CustomRootTrust, CustomTrustStore = <union of all namespace roots>, RevocationMode = NoCheck }`. Return `false` (handshake fails) if the chain does not build. At handshake time the namespace is unknown, hence the union.
- `ServerCertificateSelector`: return the current server certificate from a hot-reloadable provider (5.3).
- **Authorization middleware** (first in the EKM pipeline after capture): resolve the namespace from the path, then require (a) a client certificate, (b) a chain to **that namespace's** roots, (c) `Subject` CN exactly in **that namespace's** allow-list (case-sensitive). Otherwise `401 Unauthenticated`.
- Trust input per namespace: the `caCertificates` array (base64 DER) and `subjectCommonName` exactly as returned by `az keyvault ekm-connection certificate show`, or PEM files. Both supported.

### 5.2 Key protection (software HSM)
- See Section 6.2 for at-rest encryption.
- Key material exists in plaintext only inside `EkmMock.Crypto`. No public type exposes it. Public key objects (`n`, `e`) are the only key data that may leave.
- No API, console page, export, log or error returns secret or private key material. A test **MUST** scan all console API responses, log output and exports after a full test run for the raw key bytes (in base64, base64url and hex) and fail if found.
- DEKs passed in or out of wrap/unwrap are zeroed after use with `CryptographicOperations.ZeroMemory` (best effort; document the limits of managed memory in the README).

### 5.3 Server certificate
- PEM chain + key from files. Hot-reload on file change (`FileSystemWatcher` plus a 60 s poll fallback) and on console upload, without dropping connections.
- The SAN must equal the public FQDN registered with `--host` (public-internet model) or `server_subject_common_name` (Private Link). The console shows SAN, issuer, expiry and warns 30 days before expiry.

### 5.4 Web console security
- The console runs on its **own Kestrel endpoint and port** (default 8080). EKM routes **MUST** return 404 on the console port, and console/admin routes **MUST** return 404 on the EKM port. Enforce with a branch on `HttpContext.Connection.LocalPort`, not just host filters. Test both directions.
- Auth modes (`Console:Auth`):
  - `LoopbackOnly` (default): no sign-in, and the console binds to `127.0.0.1` only. The app **MUST** refuse to start if `LoopbackOnly` is combined with a non-loopback bind address. Reach it via SSH tunnel or `docker` port mapping on your laptop.
  - `EntraId`: OIDC sign-in with Microsoft.Identity.Web. Access limited to configured user object IDs or a security group. Required for any non-loopback bind.
- Console endpoint uses HTTPS (its own certificate; may be the same as the EKM server certificate). No client certificate required.
- Antiforgery on all state-changing console actions. Destroying a key requires typing the key name.
- Every console action that changes state (keys, trust, certificates, faults, settings, reveal of a secret) is written to the **audit log** with user, time, action and target.

### 5.5 Container hardening
- Run as non-root (`USER $APP_UID`). Read-only root filesystem except the data volume.
- Secrets (master key, console client secret) from environment variables or files (Docker/Kubernetes secrets). Never from `appsettings.json`. Never logged or shown.
- Kestrel limits on the EKM endpoint: `RequestHeadersTimeout` 2 s, `KeepAliveTimeout` 120 s, keep-alive on (Managed HSM reuses connections, and a new TLS handshake per call eats the latency budget).

---

## 6. Software HSM engine (`EkmMock.Crypto`)

### 6.1 Interfaces
```csharp
public interface ICryptoBackend
{
    BackendInfo Info { get; }                       // vendor/product for /info
    bool IsAvailable { get; }
    KeyMetadata? GetMetadata(KeyRef key);           // null = not found
    byte[] Wrap(KeyRef key, WrapAlgorithm alg, ReadOnlySpan<byte> dek);
    byte[] Unwrap(KeyRef key, WrapAlgorithm alg, ReadOnlySpan<byte> wrapped);
}
public interface IKeyManager
{
    KeyInfo Create(string ns, string name, KeyType type, int size);
    KeyInfo Import(string ns, string name, KeyType type, ReadOnlySpan<byte> material); // test vectors only, off by default
    void SetEnabled(KeyRef key, bool enabled);
    void SetExpiry(KeyRef key, DateTimeOffset? notAfter);
    void Destroy(KeyRef key);                        // irreversible crypto-shred
    IReadOnlyList<KeyInfo> List(string? ns = null);  // never includes material
}
```
`KeyRef` = (namespace, name). `KeyInfo` = name, namespace, type, size, state, created, notAfter, origin (`Generated`/`Imported`), usage counters, last used, public key (RSA only).

### 6.2 Key store
- File `keystore.json` on the data volume. One entry per key with its metadata and an **encrypted** key blob.
- Blob encryption: **AES-256-GCM** under a **Key Store Master Key (KSMK)**, 32 random bytes, 12-byte random nonce per blob, AAD = `"ekmmock:v1:" + namespace + ":" + name + ":" + type + ":" + size`. RSA private keys are serialised as PKCS#8 before encryption.
- KSMK source: `EKMMOCK_MASTER_KEY` (base64) or `EKMMOCK_MASTER_KEY_FILE`. `ekmmock init` generates one. If missing at startup, refuse to start (unless `--dev` creates a throw-away one and shows a red banner in the console).
- Writes are atomic (temp file + rename) and serialised by a lock. Load everything into memory at startup; never read the file on the hot path.
- If a blob fails GCM authentication at load (tampered file or wrong master key), mark that key `Corrupt` (wrap/unwrap return `503 HsmUnavailable` for it), keep loading the rest, and show it in red in the console.
- **Destroy** removes the blob and writes a tombstone (name, namespace, destroyed-at, by whom) so the console can show "destroyed" and the name cannot be reused by accident. Requests for a destroyed key return `404 KeyNotFound`.
- Key import (for RFC test vectors) is disabled unless `EKMMOCK_ALLOW_KEY_IMPORT=true`; imported keys carry `origin=Imported` and a badge in the console.

### 6.3 Namespaces
- A namespace = one path prefix + its client trust (CN list + root CAs) + its keys. The no-prefix namespace is `_default`.
- Same key name may exist in different namespaces.
- Namespaces are managed in the console and stored in `namespaces.json` on the data volume (atomic writes, audit-logged). `appsettings.json` can seed them at first start.

### 6.4 Algorithms
- **AES Key Wrap (RFC 3394) and with Padding (RFC 5649):** .NET has no built-in API for these. Implement them in `AesKeyWrap.cs` on top of `Aes.EncryptEcb` / `Aes.DecryptEcb` (single-block operations), with the integrity check compared using `CryptographicOperations.FixedTimeEquals`. If the .NET version in use does ship a key-wrap API, use it and keep the own implementation only as a test cross-check. Record the decision.
- **RSA-OAEP:** `RSA.Encrypt` / `RSA.Decrypt` with `OaepSHA256` or `OaepSHA1`. RSA wrap uses the public key, unwrap the private key.
- **Thread safety:** do not assume `RSA` or `Aes` instances are safe for concurrent use. Use a small per-key object pool (`Microsoft.Extensions.ObjectPool`) or create per call from cached material, whichever benchmarks faster. Record the choice.
- **Key generation:** AES via `RandomNumberGenerator.GetBytes(32)`; RSA via `RSA.Create(size)`, exponent 65537.

### 6.5 Startup self-test (before the EKM listener accepts traffic)
- AES-KW: RFC 3394 §4.6 test vector (256-bit KEK, 256-bit key data).
- AES-KWP: RFC 5649 §6 test vectors (20-byte and 7-byte key data).
- RSA-OAEP-256 and RSA-OAEP: round trip with an ephemeral 2048-bit key, plus a cross-check that a manual OAEP decode (or a second, independently created `RSA` instance from exported parameters) recovers the same plaintext.
- Per stored key: one wrap/unwrap round trip with a random 32-byte DEK (also warms up the code paths and pools).
- Results are shown on the console's About page. If a test fails, that algorithm (or key) is unavailable (`400 UnsupportedAlgorithm` / `503`). With `SelfTest:Strict=true` the app refuses to start.

---

## 7. Process and endpoint layout

```
Kestrel
├── EKM endpoint     0.0.0.0:8443 (exposed as 443)  TLS 1.3 + mTLS
│     ConnectionCapture → TLS → RequestCapture → Faults → Auth → Limits → EKM handlers → ICryptoBackend
└── Console endpoint 127.0.0.1:8080 (or 0.0.0.0 with EntraId)  HTTPS
      Blazor console, /api/console/* (REST for the CLI), /metrics, /healthz, /readyz
```

- Both endpoints are configurable (`Endpoints:Ekm:Url`, `Endpoints:Console:Url`).
- `ConnectionCapture` is Kestrel connection middleware added **before** `UseHttps` on the EKM listen options, so it sees connections that fail the TLS handshake (wrong CA, TLS 1.2, no common cipher) and records them as **connection events** (Section 8.2).
- `/healthz` (process alive), `/readyz` (key store loaded, self-test passed, EKM listener up).
- `/api/console/*`: JSON API behind the same console auth, used by the Blazor pages and the `ekmmock` CLI (keys, namespaces, trust import, certificates, faults, inspector export).

---

## 8. Traffic inspector (the "see every call" feature)

### 8.1 What is captured, per HTTP exchange on the EKM endpoint
Every request **including rejected ones** (401, 404, 405, 429, 5xx, oversized bodies):

| Group | Fields |
|---|---|
| Identity | exchange id (sequential), connection id, received at (UTC, µs), remote IP:port |
| TLS | protocol, cipher suite, ALPN (h1/h2), SNI host name, session resumed (if available), handshake time for new connections |
| Client certificate | present?, subject, issuer, serial, thumbprint (SHA-256), not before/after, chain result, CN allowed?, namespace matched |
| Request | method, raw path + query, parsed prefix / namespace / key / op / api-version, headers, body (raw text + pretty JSON), body size |
| EKM context | `request_id`, `correlation_id`, `pool_name`, `alg` |
| Response | status, `code` (if error), headers, body, body size |
| Timing | total server time, auth, crypto engine time, injected delay, queue wait; **budget status**: green < 150 ms, amber 150–250 ms, red > 250 ms |
| Key | key type/size, usage counter after the call |
| Faults | which fault rule fired, if any |

### 8.2 Connection events
Connection opened, TLS handshake succeeded (protocol, cipher, client cert subject), **TLS handshake failed (reason)**, connection closed (duration, number of requests on it). Shown in their own tab and inline in the live stream (toggle). This is how you see a misconfigured `--server-ca-certificate` or a client trust problem that never becomes an HTTP request.

### 8.3 Capture pipeline
- Capture middleware runs first in the EKM HTTP pipeline. It buffers the request body (`EnableBuffering`, max 16 KiB) and wraps the response body stream to copy at most 16 KiB.
- Records go into a bounded `Channel<T>` (drop-oldest when full, counted in a metric and shown in the console). A background consumer writes them to:
  - an **in-memory ring buffer** (default 10,000 exchanges, configurable),
  - optional **JSONL files** on the data volume (`Inspector:Persist=true`, daily rotation, size cap), always written in masked form,
  - the Blazor hub for live push to open consoles.
- **Overhead MUST be under 1 ms at p99** per request (benchmark test). The capture path never awaits the consumer.

### 8.4 Secret handling in the inspector
Plaintext DEKs appear in **wrap requests** and **unwrap responses**. Wrapped values (ciphertext) are not secret and are always shown.
- `Inspector:SecretDisplay`:
  - `Masked` (default): show length and a **fingerprint** = first 12 hex characters of SHA-256 of the raw bytes, for example `32 bytes · fp 3f9a1c07b2e4`. The same DEK produces the same fingerprint, so you can see that what was wrapped is exactly what came back from unwrap without seeing the key.
  - `Reveal`: masked, with a per-field "Reveal" button. Each reveal is audit-logged. Only allowed if the process starts with `EKMMOCK_INSPECTOR_ALLOW_REVEAL=true`.
- The raw (unmasked) value is kept **in memory only**, and only when reveal is allowed. It is never persisted or exported.
- Exports and JSONL are always masked.

### 8.5 Console pages

1. **Live traffic** (start page)
   - Streaming table, newest on top: time, op, namespace, key, alg, status (coloured), latency (with budget colour), client CN, `correlation_id` (short).
   - Pause/resume, clear view, auto-scroll toggle.
   - Filters: op, status class (2xx/4xx/5xx), namespace, key, client CN, `correlation_id` / `pool_name` search, "only errors", "only over budget", "hide health probes (`info`)".
   - Row click opens the detail panel.
2. **Exchange detail**
   - Tabs: Overview, TLS & client certificate, Request (headers + pretty JSON + raw), Response (same), Timing (waterfall bar: queue / auth / delay / crypto / total vs the 250 ms line).
   - Copy buttons for JSON and `correlation_id`.
   - A ready-made KQL snippet that finds the matching `EkmProxyOperation` record in the Managed HSM diagnostic logs for this `correlation_id`.
   - **Replay** button (sends the same request again through the EKM endpoint using the console's test client certificate), only enabled when the raw body is available (8.4).
3. **Connections**: connection events (8.2), open connections, requests per connection, TLS resumption rate.
4. **Dashboard**: requests per minute by op, latency p50/p95/p99 per op over time (last 15 min / 1 h), share over 250 ms, errors by code, **Managed HSM heartbeat** ("last `info` call 14 s ago from CN …", red if > 60 s), dropped-capture counter.
5. **Keys**: per namespace, list with type, size, state, origin, created, last used, wrap/unwrap counts. Actions: create, enable/disable, set/clear expiry, destroy (type name to confirm). Key detail shows the RSA public key (PEM and JWK `n`/`e`) and the exact command to register it:
   `az keyvault key create --hsm-name <hsm> --name <ref-name> --external-key-id <key-name>`
6. **Namespaces & trust**: create/edit/delete namespaces (prefix validated per 4.2). "Import Managed HSM client trust": paste the JSON from `az keyvault ekm-connection certificate show`; the page parses it and shows the CN and each CA's subject, issuer and expiry before saving. Shows the matching `az keyvault ekm-connection create … --path-prefix …` command.
7. **Certificates**: current EKM server certificate (SAN, issuer, chain, expiry), upload new PEM (hot reload), generate a test root CA + server certificate for a given FQDN, download `root-ca.pem` for `--server-ca-certificate`.
8. **Playground**: pick namespace, key and algorithm; enter a DEK (hex, base64url or "generate random 32 bytes") or a wrapped value. Two modes:
   - **Direct:** calls the engine in-process (not captured as EKM traffic).
   - **Via EKM endpoint:** sends a real HTTPS request to the EKM endpoint with the built-in test client certificate (a namespace must trust the test CA). It shows up in Live traffic like any other call.
   Shows the result, fingerprints, and a one-click "unwrap this result" to prove the round trip.
9. **Fault injection** (Section 10.2).
10. **Audit log**: who did what, when.
11. **About / settings**: version, effective configuration (secrets redacted), self-test results, master-key status (loaded / dev mode), data volume path and sizes.

---

## 9. Logging and metrics

- One structured log line per EKM request with the fields of 8.1 minus bodies and headers (`exchange_id`, `request_id`, `correlation_id`, `pool_name`, `namespace`, `op`, `key`, `alg`, `status`, `error_code`, `client_cn`, `duration_ms`, `crypto_ms`, `injected_delay_ms`). **Never** log `value`, `n`, `e`, bodies, PINs or master keys. A captured-log test **MUST** prove it.
- Warning when `duration_ms` > 150, error when > 250.
- Metrics (console port `/metrics`): `ekmmock_requests_total{op,status,namespace}`, `ekmmock_request_duration_seconds{op}` (buckets 0.005, 0.01, 0.025, 0.05, 0.1, 0.15, 0.2, 0.25, 0.5, 1), `ekmmock_crypto_duration_seconds{op,alg}`, `ekmmock_budget_exceeded_total{op}`, `ekmmock_tls_handshake_failures_total{reason}`, `ekmmock_inspector_dropped_total`, `ekmmock_inflight_requests`.
- `docs/RUNBOOK.md` must include the KQL from the Learn quickstart and explain correlating the console's `correlation_id` with Azure-side `EkmProxyOperation` entries.

---

## 10. Latency, limits and fault injection

### 10.1 Budget enforcement
- `Limits:LatencyBudgetMs` (default 250) and `Limits:InternalDeadlineMs` (default 200). Each request gets a `CancellationTokenSource` with the internal deadline.
- `Limits:MaxConcurrency` (default 64): over the limit, return `429` immediately. If the deadline passes before the crypto call starts, return `429` immediately. A fast, explicit error beats a vague Azure-side timeout.
- Crypto calls are synchronous and not cancelled once started; if one ends after the deadline, still return the result and count it in `ekmmock_budget_exceeded_total`.

### 10.2 Fault injection (test feature)
Only available when the process starts with `EKMMOCK_ENABLE_FAULTS=true`; otherwise the page is read-only and shows "disabled". Rules apply globally or per namespace / key / op, and are managed in the console (and `/api/console/faults`):
- **Delay:** fixed `delayMs` or uniform `minMs`–`maxMs`, applied before the crypto call. Use it to simulate a distant network HSM and find where Azure starts failing (around 250 ms).
- **Error rate:** 0–100% with status `429`, `500` or `503`.
- **HSM offline:** engine reports unavailable; `info` and all ops return `503`.
- **Key disabled (temporary):** same as disabling, without touching the key store.
- **Blackhole:** accept the request and never respond (until the client gives up). Shows Managed HSM timeout behaviour.
- **Close connection:** abort the connection without a response.
- Every fault that fires is recorded on the exchange and shown with a badge in Live traffic. A banner at the top of every console page says faults are active.

---

## 11. Packaging and deployment

### 11.1 Container
- Multi-stage Dockerfile: build with `mcr.microsoft.com/dotnet/sdk:10.0`, run on `mcr.microsoft.com/dotnet/aspnet:10.0`. ReadyToRun publish for faster start. Server GC.
- Image contains the server and the `ekmmock` CLI.
- Volume `/data` (key store, namespaces, audit log, inspector JSONL, certificates). Config from `/app/appsettings.json` + environment.
- Healthcheck hits `/healthz` on the console port.

### 11.2 Local (docker-compose)
- One service, EKM port `443:8443`, console `127.0.0.1:8080:8080`.
- `make dev` (or `dotnet run`) generates dev certificates (test root CA, server certificate for `localhost`, a fake "Managed HSM" client CA + client certificate with CN `test.managedhsmclient.local`), creates `_default` with sample keys `aes-key-1` (AES-256) and `rsa-key-1` (RSA-2048), and trusts the fake client CA, so `ekmmock test conformance` runs immediately.

### 11.3 Azure test deployment (public-internet model)
Provide Bicep + script under `deploy/azure/`, in the **same region as the Managed HSM pool**:
- **Recommended: small Linux VM with Docker** (Ubuntu, B2s is enough). Public IP + DNS label, NSG allows inbound 443 from anywhere (required, Managed HSM IPs are not static) and 22 from your IP only. The console stays on loopback; open it with `ssh -L 8080:127.0.0.1:8080`. Simplest and safest way to get the UI.
- **Alternative: Azure Container Instances** with a public IP and DNS name label, Azure Files for `/data`. ACI does TCP pass-through, so mTLS terminates in the app. ACI exposes the container port directly (no port remapping), so the EKM endpoint must listen on 443 inside the container; check whether the non-root user can bind it there (see open questions). The console must then use `EntraId` auth on a second public port.
- **Do not** put a TLS-terminating front end (Application Gateway, Front Door, Container Apps HTTP ingress) in front of the EKM endpoint. The app must see the Managed HSM client certificate itself.
- Master key via a secure parameter/secret, never in the template output.

### 11.4 Private Link later
Private Link (preview) needs a Standard Load Balancer + Private Link Service in front of the EKM endpoint. Out of scope, but keep the server name used for the certificate SAN configurable and independent of the host name, because Managed HSM then validates against `server_subject_common_name`.

---

## 12. CLI (`ekmmock`)

```
ekmmock init --data /data                         # generate master key, data folders
ekmmock certs ca|server|client …                  # test PKI only
ekmmock key create|list|enable|disable|expire|destroy --console https://127.0.0.1:8080 …
ekmmock trust import --ns _default --json mhsm-client.json --console …
ekmmock test conformance --url https://<fqdn>[/prefix] --client-cert … --client-key … --ca root-ca.pem
ekmmock test bench --url … --op unwrapkey --key aes-key-1 --alg A256KWP --concurrency 16 --duration 60s
```
- Key and trust commands call `/api/console/*` (same auth as the console; for `EntraId`, device-code sign-in).
- `test conformance` runs every acceptance test in Section 14 that can run from outside, prints PASS/FAIL per test and writes a JSON report.
- `test bench` reports p50/p90/p99/max latency, throughput, errors per status and the **percentage over 250 ms**. Its requests appear in the console like any other traffic.
- After a successful conformance run, print the `az` commands for Section 15 with FQDN, prefix and key names filled in.

---

## 13. Milestones (build in this order)

| # | Deliverable | Done when |
|---|---|---|
| M1 | `EkmMock.Crypto`: AES-KW/KWP, RSA-OAEP, key generation, encrypted key store, namespaces, self-test | RFC 3394/5649 vectors pass; tamper and wrong-master-key tests; no-material-leak tests on public types |
| M2 | EKM API: routing (multi-prefix), request/response types, ProxyError, base64url, handlers over `ICryptoBackend` | Integration tests over plain HTTP via `WebApplicationFactory` |
| M3 | EKM endpoint mTLS: TLS 1.3, cipher policy, custom root trust, per-namespace CN/CA auth, 401 handling, certificate hot-reload, connection capture of handshake failures | Tests on real Kestrel with generated certificates: valid, wrong CN, wrong CA, no cert, TLS 1.2 refused, handshake-failure event recorded |
| M4 | Inspector capture pipeline, ring buffer, JSONL, masking/fingerprints, overhead benchmark | Every request incl. rejected ones captured; < 1 ms p99 overhead; masking tests |
| M5 | Console shell + auth modes + endpoint separation; Live traffic, Exchange detail, Connections, Dashboard | Port-separation tests; LoopbackOnly-with-public-bind refuses to start; live update visible within 1 s (bUnit or Playwright test) |
| M6 | Console: Keys, Namespaces & trust (incl. JSON import), Certificates, Playground, Audit log, About | Playground "via EKM endpoint" round trip shows in Live traffic; audit entries written |
| M7 | Limits, fault injection, metrics, structured logs | Delay / error / offline / blackhole tests; log-redaction test; metrics scrape test |
| M8 | `ekmmock` CLI: init, certs, key/trust commands, conformance, bench | Full conformance suite green locally |
| M9 | Dockerfile, compose, Bicep (VM + ACI), README, RUNBOOK, DECISIONS, OPEN-QUESTIONS, RESULTS template | `docker compose up` then `ekmmock test conformance` green on a clean machine |

GitHub Actions CI: `dotnet build -warnaserror`, `dotnet test`, `dotnet list package --vulnerable`, build the image, run conformance against the container.

---

## 14. Acceptance tests

**EKM protocol**
1. `info` returns 200 with all five fields; returns 503 when "HSM offline" is on.
2. Missing `api-version` → 400; `api-version=9.9` → 400.
3. Key-name of 65 characters or containing `_` or `.` → 400 `InvalidKeyName`.
4. Unknown key → 404; key in another namespace → 404; destroyed key → 404.
5. Metadata for AES-256 matches 4.7 exactly; RSA `n` decodes to the right modulus, `e` = `AQAB`, no leading zero byte.
6. Wrap/unwrap round trip for every algorithm and DEK sizes 16, 24, 32, 64 bytes (and 1–4096 for KWP; RSA up to its limit).
7. AES-KW and AES-KWP output matches RFC 3394 / RFC 5649 vectors with an imported RFC KEK.
8. RSA-OAEP-256 / RSA-OAEP ciphertext from EkmMock decrypts with an independent `RSA` instance built from exported parameters (and the reverse).
9. Algorithm/key-type mismatch → 400 `UnsupportedAlgorithm`.
10. Tampered wrapped value → 400 `InvalidCiphertext` (not 500).
11. Disabled key: wrap/unwrap → 403 `KeyDisabled`, metadata → 200. Expired → 403 `KeyExpired`.
12. Padded and unpadded base64url accepted; `+`/`/` → 400; output always unpadded.
13. Keys and namespaces survive a restart; a wrapped DEK from before the restart unwraps after it.

**Security**
14. TLS 1.2 refused. No client cert → 401. Untrusted CA → handshake fails. Trusted CA, wrong CN → 401. CN allowed on namespace A, used on B → 401.
15. Server certificate replaced → served within 60 s, no failed in-flight requests.
16. EKM paths on the console port → 404; console paths on the EKM port → 404.
17. `LoopbackOnly` + non-loopback bind → app refuses to start.
18. Leak scan: after a full test run, no raw key material (base64, base64url, hex) appears in any console API response, export, JSONL file or log.
19. Key store file contains no raw key bytes; flipping one byte in a blob marks that key `Corrupt`; wrong master key → all keys `Corrupt`, app still serves `info` with 503 for those keys' operations.

**Inspector**
20. Every EKM request (2xx, 4xx including 401, 429, 5xx) appears in Live traffic within 1 s, with request and response bodies.
21. A TLS handshake failure appears as a connection event with a reason.
22. Default masking: wrap-request and unwrap-response `value` show length + fingerprint only; fingerprints of wrap input and unwrap output match.
23. Reveal impossible without `EKMMOCK_INSPECTOR_ALLOW_REVEAL=true`; when allowed, each reveal is audit-logged.
24. Inspector overhead < 1 ms p99; when the channel is full, oldest entries drop and the counter increments; the EKM request is never slowed.

**Latency and resilience**
25. Local bench at concurrency 16 for 60 s: p99 < 10 ms for AES unwrap, < 30 ms for RSA-2048 unwrap, < 100 ms for RSA-4096 unwrap, 0% over 250 ms. Record the real numbers in README as the baseline.
26. Fault delay 300 ms → client sees > 250 ms; budget metric increments; exchange shows red with the fault badge.
27. Concurrency limit exceeded → immediate 429.

---

## 15. End-to-end Azure test (script as `deploy/azure/e2e.sh`)

Prerequisites: a Managed HSM in an Azure **public** region (EKM excludes Azure Government and Azure China), the subscription feature `Microsoft.KeyVault/MHSM_EKM` registered, and the roles **Managed HSM EKM Administrator** and **Managed HSM Crypto User**.

```bash
# 1. Trust the Managed HSM client identity (or paste it in the console: Namespaces & trust)
az keyvault ekm-connection certificate show --hsm-name $HSM > mhsm-client.json
ekmmock trust import --ns _default --json mhsm-client.json --console https://127.0.0.1:8080

# 2. Create the connection (public internet, port 443, ROOT CA not leaf)
az keyvault ekm-connection create --hsm-name $HSM --host $FQDN \
  --server-ca-certificate root-ca.pem [--path-prefix /contoso/prod]
az keyvault ekm-connection check --hsm-name $HSM      # watch it arrive in Live traffic

# 3. Register external key references (watch the metadata calls arrive)
az keyvault key create --hsm-name $HSM --name ekm-aes --external-key-id aes-key-1
az keyvault key create --hsm-name $HSM --name ekm-rsa --external-key-id rsa-key-1

# 4. Round trip through Managed HSM (data plane, api-version 7.5)
az rest --method POST --resource https://managedhsm.azure.net \
  --uri "https://$HSM.managedhsm.azure.net/keys/ekm-aes/wrapkey?api-version=7.5" \
  --headers Content-Type=application/json --body @wrap-a256kw.json
# then unwrapkey with the returned value; compare with the original DEK (fingerprints match in the console)
```

Scenarios to run and record in `docs/RESULTS.md`:
- **Baseline:** 1,000 unwraps via Managed HSM. Compare EkmMock server time with the Azure-side `EkmProxyOperation` latency; the difference is roughly network + Managed HSM overhead.
- **Latency sweep:** inject 50, 100, 150, 200, 240, 260, 300 ms. Note where Managed HSM starts failing and what the Azure-side error looks like.
- **Disable key / destroy key:** effect on a CMK-protected Storage account and how long until the workload is affected.
- **HSM offline / blackhole:** effect on `az keyvault ekm-connection check` and on the workload; watch the heartbeat on the dashboard.
- **What Azure actually sends:** from the inspector, record which `alg`, DEK sizes, HTTP version and connection reuse Managed HSM uses for each key type and service.

Clean-up order: move workloads off the key, then `az keyvault key delete`, then `az keyvault ekm-connection delete`, then destroy keys and delete the VM. Destroying a key or losing the master key makes any data protected by it unrecoverable.

---

## 16. Repository layout

```
/src/EkmMock.Crypto/        software HSM engine, AesKeyWrap, key store, namespaces, self-test (no ASP.NET deps)
/src/EkmMock.Server/        Kestrel host, EKM endpoint, auth, limits, faults, inspector, console API
/src/EkmMock.Server/Console/  Blazor components and pages
/src/EkmMock.Cli/           ekmmock tool (System.CommandLine)
/tests/EkmMock.Crypto.Tests/
/tests/EkmMock.Server.Tests/   real-Kestrel mTLS tests, inspector tests, leak scan
/tests/EkmMock.Console.Tests/  bUnit component tests
/deploy/docker/            Dockerfile, compose.yaml
/deploy/azure/             vm.bicep, aci.bicep, e2e.sh
/docs/                     README, RUNBOOK, DECISIONS, OPEN-QUESTIONS, RESULTS
Directory.Packages.props, EkmMock.sln
```

### Example `appsettings.json`

```json
{
  "Endpoints": {
    "Ekm":     { "Url": "https://0.0.0.0:8443" },
    "Console": { "Url": "https://127.0.0.1:8080" }
  },
  "Tls": {
    "ServerName": "ekm-test.westeurope.cloudapp.azure.com",
    "CertFile": "/data/tls/server.crt",
    "KeyFile": "/data/tls/server.key"
  },
  "Console": { "Auth": "LoopbackOnly", "EntraId": { "TenantId": "", "ClientId": "", "AllowedObjectIds": [], "AllowedGroupId": "" } },
  "ProxyInfo": { "ApiVersion": "0.1-preview", "ProxyVendor": "Remco Test", "ProxyName": "EkmMock v0.2.0",
                 "EkmVendor": "EkmMock", "EkmProduct": "EkmMock Software HSM v0.2.0" },
  "Data": { "Path": "/data" },
  "SeedNamespaces": [
    { "Prefix": "", "Name": "_default",
      "ClientTrust": { "SubjectCommonNames": ["contoso.managedhsmclient.azure.net"], "CaCertificatesDerBase64": ["MIIDj..."] } }
  ],
  "Limits": { "LatencyBudgetMs": 250, "InternalDeadlineMs": 200, "MaxConcurrency": 64 },
  "Inspector": { "RingBufferSize": 10000, "Persist": true, "SecretDisplay": "Masked", "MaxBodyBytes": 16384 },
  "SelfTest": { "Strict": false }
}
```
Environment-only settings: `EKMMOCK_MASTER_KEY` / `EKMMOCK_MASTER_KEY_FILE`, `EKMMOCK_ENABLE_FAULTS`, `EKMMOCK_INSPECTOR_ALLOW_REVEAL`, `EKMMOCK_ALLOW_KEY_IMPORT`, Entra client secret.

---

## 17. Open questions (seed `docs/OPEN-QUESTIONS.md`)

1. `api_version` in the `info` response: documented API version is `0.1-preview`, Learn examples show `"1.0"`. Confirm what `az keyvault ekm-connection check` accepts (watch it in the inspector).
2. Does Managed HSM send padded or unpadded base64url? EkmMock accepts both; confirm from captured traffic.
3. Should a disabled key still return metadata (current choice: yes)?
4. Which `alg` values and DEK sizes do Azure services (for example Storage) actually send for RSA vs AES external keys?
5. Does Managed HSM use HTTP/1.1 or HTTP/2, and how many connections does it keep open and reuse?
6. ACI: can the non-root container user bind port 443 (no port remapping in ACI)? If not, document the fallback (VM, or root in ACI only).
7. Does `System.Buffers.Text.Base64Url` decoding accept padding in the .NET version used? If not, normalise before decoding.
8. Does the .NET version used ship an AES Key Wrap API (Section 6.4)?
