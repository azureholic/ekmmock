# Open questions

Seeded from spec section 17. If the Microsoft Learn EKM Proxy API reference conflicts with the spec, add the discrepancy here
and stop the affected work.

## Status summary

One line per question; the entries below are the source of truth. **open** = undecided or unknown and answerable locally; **answered** = answered or resolved (the entry says how);
**not verifiable offline** = can only be answered with a real Azure Managed HSM, Entra tenant, ACI or Azure VM (see [RESULTS](RESULTS.md) section 3). Status as of M9 part 2.

| Id | Topic | Status |
|---|---|---|
| 1 | `info` `api_version` accepted by `check` | not verifiable offline |
| 2 | Padded or unpadded base64url from Managed HSM | not verifiable offline |
| 3 | Metadata for a disabled key | not verifiable offline (choice implemented) |
| 4 | `alg` and DEK sizes Azure services send | not verifiable offline |
| 5 | HTTP version and connection reuse of Managed HSM | not verifiable offline |
| 6 | Non-root binding of port 443 (ACI) | answered for Docker; not verifiable offline for ACI |
| 7 | Base64Url padding in .NET | answered |
| 8 | AES key wrap API in .NET | answered |
| 9 | Error code for 405 | open |
| 10 | Body on `info` | not verifiable offline |
| 11 | Exact `Content-Type` Managed HSM sends | not verifiable offline |
| 12 | `api-version` strictness | open |
| 13 | Optional context fields of a wrong type | open |
| 14 | Upper DEK size for A256KW | open |
| 15 | Prefix shadows a same-named key in `_default` | open |
| 16 | Percent-encoded `/` in a key name | answered |
| 17 | No certificate: handshake failure or JSON 401 | open (confirm with Azure) |
| 18 | `caCertificates` always self-signed roots? | not verifiable offline |
| 19 | Intermediates and `clientAuth` EKU from Managed HSM | not verifiable offline |
| 20 | Expired client certificate: 401 or handshake | open |
| 21 | Cipher-suite enforcement on Windows | open |
| 22 | 404 versus 401 for unknown prefixes | open |
| 23 | TLS session resumption disabled | open |
| 24 | Chunked body of exactly 16 KiB | open |
| 25 | Windows CA-store side effect | open |
| 26 | `AzureDiagnostics` column for `correlation_id` | not verifiable offline |
| 27 | What Managed HSM really sends is observable | not verifiable offline |
| 28 | Fingerprints of low-entropy secrets | open |
| 29 | `EnableBuffering` versus stream wrapping | open |
| 30 | Bodies above 16 KiB not captured | open |
| 31 | Resumption in the inspector | open |
| 32 | 150/250 ms log levels | answered (M7) |
| 33 | Docker port mapping versus loopback bind | answered (deliberate deviation, M9) |
| 34 | Entra sign-in against a real tenant | not verifiable offline |
| 35 | Group-claim overage | open |
| 36 | Circuit identity not revalidated | open |
| 37 | Fluent UI Blazor v4 versus v5 | open |
| 38 | CLI authentication against `EntraId` | answered (M8; real tenant is 53) |
| 39 | No file upload for trust import | open |
| 40 | Console test CA is per process | open |
| 41 | Generated root CA cannot re-issue | open |
| 42 | `az` commands shown by the console not run | not verifiable offline (see 71) |
| 43 | Self-test cases only for keys at startup | open |
| 44 | Toast placement | open |
| 45 | `--dev` without sample keys | answered (see 60) |
| 46 | Windows CNG key file leak in tests | open (reduced) |
| 47 | Handshake flake under load | open |
| 48 | Managed HSM behaviour on 429, 5xx, blackhole, close | not verifiable offline |
| 49 | Injected delay and the deadline | open |
| 50 | Budget metric counts the deadline | open |
| 51 | Faults answer before authentication | open |
| 52 | `HttpClient` early responses | open |
| 53 | Entra bearer path against a real tenant | not verifiable offline |
| 54 | Log lines can be dropped under overload | open |
| 55 | ~10 s stalls at 30k req/s | open (re-measure off-box) |
| 56 | Test PKI pollutes the Windows store | open |
| 57 | Two-phase persistence test | answered (by design) |
| 58 | Windows ACL for owner-only files | open |
| 59 | No disk token cache in the CLI | open |
| 60 | Fresh `--dev` has no sample keys | answered (dev compose seeds them) |
| 61 | Image cannot be built from nuget.org on the dev network | open (CI path verified) |
| 62 | Health check does not verify the console certificate | open |
| 63 | Data Protection keys unencrypted | open |
| 64 | Server GC and R2R on the 2-vCPU VM | not verifiable offline |
| 65 | Browser tests need their own CI job | open |
| 66 | No licence declared | open (owner decision) |
| 67 | Source address of loopback-published connections | open |
| 68 | Shared-runner timing | open |
| 69 | `docker compose up --wait` not used | answered |
| 70 | `EkmProxyOperation` versus the real operation names | answered (Learn logging article used) |
| 71 | `az keyvault ekm-connection` availability and syntax | answered for the CLI surface; behaviour not verifiable offline |
| 72 | VM boot flow (cloud-init, Docker, certificate generation) | not verifiable offline |
| 73 | ACI: 443 as non-root, SMB semantics, `runAsUser`, secret volume | not verifiable offline |
| 74 | `e2e.sh` against a real Managed HSM | not verifiable offline |
| 75 | `DurationMs` in `AzureDiagnostics` | not verifiable offline |
| 76 | Bicep type library versus the newest GA API versions | open |
| 77 | Root cause of the intermittent M3 Windows finding (a request without a certificate served as an earlier identity) | open (now fails closed) |
| 78 | The inspector byte estimate is approximate | open |
| 79 | ACI: the storage account key reads the Data Protection keys and can forge console cookies | open (documented; not verifiable offline) |

## Questions

1. `api_version` in the `info` response: documented API version is `0.1-preview`, Learn examples show `"1.0"`. Confirm what
   `az keyvault ekm-connection check` accepts (watch it in the inspector).
2. Does Managed HSM send padded or unpadded base64url? EkmMock accepts both; confirm from captured traffic.
3. Should a disabled key still return metadata (current choice: yes)?
   - **Status:** current choice implemented in M2: a disabled or expired key answers `200` for `metadata`; only wrap/unwrap are
     blocked (`403 KeyDisabled` / `403 KeyExpired`). Proven by `KeyStateTests`. Learn does not say; confirm with real Managed HSM
     behaviour (what it does when `metadata` is called for a disabled external key reference).
4. Which `alg` values and DEK sizes do Azure services (for example Storage) actually send for RSA vs AES external keys?
5. Does Managed HSM use HTTP/1.1 or HTTP/2, and how many connections does it keep open and reuse?
   - **Status (M3):** EkmMock supports both (ALPN `h2` / `http/1.1`, proven on a real listener, authorization identical, `closed.RequestCount`
     shows reuse or multiplexing per connection). What Managed HSM actually negotiates is still unknown; read it from the Connections tab (M4/M5)
     of a real connection.
6. ACI: can the non-root container user bind port 443 (no port remapping in ACI)? If not, document the fallback (VM, or root in
   ACI only).
   - **Status (M3):** EkmMock listens on `8443` by default (`Endpoints:Ekm:Url`); Learn requires TCP 443 on the *public* side, which the docker
     mapping (`443:8443`) provides on a VM. Binding 443 inside the container as non-root needs `CAP_NET_BIND_SERVICE` or
     `net.ipv4.ip_unprivileged_port_start=443`; the URL is configurable (`https://0.0.0.0:443`) and the code has no other constraint. Still open for ACI.
   - **Status (M9), measured with the real image on Docker Desktop (Linux engine, Docker 29.9.2), user 1654, `--read-only --cap-drop ALL`:**
     (A) default engine settings (`net.ipv4.ip_unprivileged_port_start=0`, which Docker sets in every container's network namespace): `Endpoints__Ekm__Url=https://0.0.0.0:443` **binds and serves**, no capability needed.
     (B) `--sysctl net.ipv4.ip_unprivileged_port_start=1024`: `SocketException (13): Permission denied`, the host exits with 139. (C) the same plus `--cap-add NET_BIND_SERVICE` for the non-root user: still denied (Docker does not make an added capability ambient for a non-root process).
     (D) `--sysctl net.ipv4.ip_unprivileged_port_start=443` (or 0): works. (E) (C) plus `no-new-privileges`: denied. A `setcap cap_net_bind_service` on the dotnet host binary would also be defeated by `no-new-privileges`, so it is not used.
     **So on Docker (the VM model) the non-root user can bind 443 by default, and the documented fallbacks are, in order: keep 8443 inside and map `443:8443` (the compose default and what the spec's VM flow does), set the sysctl (`--sysctl` / compose `sysctls:`), and as the last resort run as root in ACI only (never the default).**
     **Still unknown: ACI.** ACI exposes the container port directly (no remapping) and its sandbox's `ip_unprivileged_port_start` could not be tested from here. Test with the real image in ACI (`Endpoints__Ekm__Url=https://0.0.0.0:443`, non-root): if it logs `Permission denied` the sysctl cannot be set in ACI and the alternatives are the VM, or `--user 0` / `securityContext` root in ACI only for that deployment, documented as a deviation from spec 5.5.
   - **Status (M9 part 2):** `deploy/azure/aci.bicep` implements exactly this (EKM on 443 inside the container, `runAsRoot` parameter default `false`), but it was **never deployed**; see 73 for everything about ACI that is still unverified. The VM template (`vm.bicep`) keeps `443:8443` and needs no privileged port inside the container.
7. Does `System.Buffers.Text.Base64Url` decoding accept padding in the .NET version used? If not, normalise before decoding.
   - **Status:** answered in M2 (measured on .NET 10.0.14, pinned by the `OQ7_*` tests in `Base64UrlTests`). `Base64Url.DecodeFromUtf8`
     and `DecodeFromChars` **accept padded input** (`AQ==`, `AQA=`) as well as unpadded, reject `+` `/` and malformed padding, and reject
     non-canonical trailing bits. They **skip whitespace silently**, so EkmMock pre-scans the input and rejects whitespace itself. No padding
     normalisation is needed. See `DECISIONS.md` "M2: Base64url".
8. Does the .NET version used ship an AES Key Wrap API (Section 6.4)?
   - **Status:** answered in M1. .NET 10.0.14 ships a public API for **RFC 5649 key wrap with padding only**
     (`Aes.EncryptKeyWrapPadded`, `DecryptKeyWrapPadded`, `TryDecryptKeyWrapPadded`, `GetKeyWrapPaddedLength`). RFC 3394 plain key
     wrap (A256KW) exists only as non-public helpers. Decision: A256KWP uses the runtime API, A256KW is implemented in
     `AesKeyWrap.cs`, and an own RFC 5649 implementation is kept as a test and self-test cross-check. See `DECISIONS.md`; a test
     pins the finding so a future .NET that adds a public RFC 3394 API is noticed.

## Added during M2

9. **Error code for `405`.** Spec 4.1 requires a ProxyError body with status 405 but lists no code. EkmMock uses `MethodNotAllowed` (with an
   `Allow: POST` header). Learn lists no 405 at all. Harmless unless Managed HSM ever sends a non-POST.
10. **Does Managed HSM always send a JSON body (with `request_context`) on `info`?** Spec 4.3 and the Learn example say every request body
    carries `request_context`, so EkmMock answers `400 InvalidRequest` when it is missing, also for `info`. If the real health probe or connection check
    sends no body, `info` would fail and the check would look unhealthy. Confirm from captured traffic (inspector, M4); relaxing it for `info` is a
    one-line change in `EkmDispatcher`.
11. **`Content-Type` details.** EkmMock accepts `application/json` case-insensitively with an optional `charset=utf-8` and rejects other types
    and other charsets with 400. Learn only says `application/json`; confirm the exact header value Managed HSM sends (for example whether it adds a charset).
12. **Strictness of `api-version`.** Exactly one `api-version` parameter, value exactly `0.1-preview` (case-sensitive); a repeated parameter is
    `400 UnsupportedApiVersion`. Learn says only "required"; it does not specify case handling or repeated parameters.
13. **Optional context fields of a wrong type.** `request_id`, `correlation_id` and `pool_name` that are not strings are ignored (they are
    correlation aids), while a missing `request_context` object is `400`. The Learn types are all strings. A mistyped `alg`/`value` is rejected by
    wrap/unwrap and ignored by `info`/`metadata`.
14. **Which algorithms may an A256KW wrap carry at the top end?** Spec 4.10 gives no upper DEK size for A256KW; the 16 KiB body limit bounds it
    (about 12 KB). Confirm that Azure services never send anything near that.
15. **Prefix shadows a same-named key in `_default`.** With a namespace prefix `contoso` and `_default`, the path `/contoso/wrapkey` belongs to
    namespace `contoso` (and is a 404 there), never to a `_default` key called `contoso`. This follows from longest-prefix matching (spec 4.2);
    worth a console warning when a namespace prefix equals an existing key name in `_default` (M6).
16. **Percent-encoded `/` in a key name** (`%2F`): real Kestrel keeps it undecoded, so it is `400 InvalidKeyName`; the in-process test host
    decodes it and the request becomes a routing `404`. Re-verify with real Kestrel tests in M3.
    - **Status:** answered in M3 by `APercentEncodedSlashInTheKeyName_IsInvalidKeyName_OnRealKestrel` (raw TLS socket, real Kestrel: `400 InvalidKeyName`).

**Learn comparison (M2):** no conflict between the implemented contract and the Learn "EKM Proxy API reference" was found; see `DECISIONS.md`
"M2: Learn comparison". Learn's `info` example shows `"api_version": "1.0"` (open question 1) and its 403 row mentions "the operation isn't
supported" (`OperationNotAllowed` exists in the code but nothing emits it yet).

## Added during M3

17. **Learn says a client without a valid certificate "can't complete the handshake"; the spec makes a missing certificate a JSON 401.** Learn
    ("Configure networking and mTLS", public-internet note) states that an attacker without a valid Managed HSM client certificate cannot complete
    the handshake. Spec 5.1 requires `ClientCertificateMode.AllowCertificate` so that a request *without* a certificate reaches the middleware and
    gets the `401 Unauthenticated` the EKM Proxy API reference lists. EkmMock follows the spec: a certificate that does not chain to any
    namespace's root CA fails the handshake; **no certificate** completes the handshake and every operation answers `401` (nothing is served
    without an authorized certificate). Not a conflict that stops work (the API reference supports the 401), but worth confirming that
    `az keyvault ekm-connection check` is happy either way. If a stricter handshake is wanted, switch to `RequireCertificate` (one line in
    `EkmKestrel.cs`) and give up the JSON 401 for the no-certificate case.
18. **Are the `caCertificates` of a pool always self-signed roots?** Learn calls them "root certificates", and a namespace must list roots: with .NET
    custom root trust an *issuing* CA listed instead of the root authenticates nobody (identical on Windows and Linux, pinned by
    `ANamespaceThatListsAnIssuingCaInsteadOfARoot_DoesNotAuthenticateItsClients`). If a real pool returns an issuing CA in `caCertificates`, the trust
    model needs `AllowUnknownCertificateAuthority` plus an explicit anchor check; confirm with real output of `az keyvault ekm-connection certificate show`.
19. **Does Managed HSM send its intermediate certificates in the handshake, and does its client certificate carry the `clientAuth` EKU?** EkmMock
    rebuilds the chain with the intermediates the client sent (never as trust anchors) and requires `clientAuth` only if an EKU is present. A client
    that does not send its issuing CA is not authenticated. Confirm from a captured real connection (M4 shows the chain result).
20. **Expired client certificate: 401 or handshake failure?** Decided: 401 (the handshake only checks the CA, time/EKU/CN are judged per request, so
    the failure is diagnosable and captured; see DECISIONS "M3: Client certificate validation"). A TLS stack that checks validity itself would
    refuse earlier; Learn does not say what the proxy should do.
21. **TLS cipher suites cannot be enforced by the TLS stack on Windows/macOS-style `CipherSuitesPolicy`-less platforms.** On Windows the policy
    throws `PlatformNotSupportedException`; EkmMock then logs a warning and closes connections that negotiated another suite *after* the handshake.
    Production (Linux/OpenSSL) enforces it in the handshake (verified in a Linux container). The only suites SChannel negotiated in testing were
    `TLS_AES_256_GCM_SHA384`; whether other Windows versions offer ChaCha20 by default was not tested.
22. **Routing precedes authentication, so an unauthenticated client can tell known from unknown path prefixes** (`404` versus `401`), and a request
    for a path no namespace claims is a `404` even without a certificate. Spec 7 and the M2 design put Route before Auth because Auth needs the
    namespace. If prefix secrecy matters, answer `401` for an unroutable path when the caller has no authorized certificate for *any* namespace; this is
    a small change in `EkmRouteMiddleware`/`EkmAuthMiddleware` and was not done because the spec does not ask for it.
23. **TLS session resumption** is disabled on the EKM endpoint (`AllowTlsResume = false`, see DECISIONS "M3: TLS stack"), so every connection is a full
    handshake and the connection event reports `Resumed = false`. Open: whether Managed HSM's latency suffers from missing resumption (it should not:
    TLS 1.3 full handshakes are one round trip, and it reuses connections). If resumption is wanted later, the per-request chain rebuild needs the
    intermediates another way, and the "client without certificate" regression tests must keep passing.
24. **A chunked request body of exactly 16384 bytes may be refused** (Kestrel counts chunk framing against `MaxRequestBodySize`); it is then the same
    `400 InvalidRequest` ProxyError as any oversized body. A `Content-Length` body of 16384 bytes is accepted, 16385 is refused. Irrelevant for the
    request sizes Managed HSM sends; noted for completeness.
25. **Windows CA-store side effect.** The Windows TLS stack caches CA certificates that it sees in the current user's `CurrentUser\CA` store. Running
    EkmMock with real or generated certificates on a Windows dev machine can therefore leave certificates there (the tests clean up their own).
    OS behaviour; Linux containers (the production target) are unaffected.

## Added during M4

26. **Which `AzureDiagnostics` column carries the proxy's `correlation_id`?** The Microsoft Learn pages "Logging and monitoring for Managed HSM external key management" and "Troubleshoot Managed HSM external key
    management" (read 9 November 2026) say to correlate Managed HSM and proxy logs by the request context fields (`request_id`, `correlation_id`, `pool_name`), by the external key identifier in `requestUri_s` and by a
    ±1 second timestamp window, and they list a correlation column as `correlationId_g` in one article and `CorrelationId` in the other, but they never state that this column *equals* the `correlation_id` that Managed HSM puts
    in `request_context`, and they list no column for `request_id` or `pool_name` at all. The inspector's KQL snippet therefore matches either column name with `column_ifexists` (no error when one does not exist) and
    offers the documented key-plus-time fallback as a second query; no column was invented. Confirm with real `EkmProxyOperation`/`AzureDiagnostics` rows next to a captured exchange (the inspector shows the three
    context fields for every exchange, including rejected ones).
27. **What Managed HSM really sends is now observable.** M4 records, per exchange, the exact request headers (open question 11: the `Content-Type` value), the request body including whether `request_context` is present on `info`
    (question 10), `alg` and DEK sizes per key type (question 4), and per connection the ALPN, the number of requests it carried and its lifetime (questions 2 and 5: padded base64url shows in the captured text of a
    wrapped value; HTTP version and connection reuse show in the Connections data). These questions stay open until someone runs it against a real pool; the data to answer them is captured.
28. **Fingerprints of low-entropy secrets.** The 12-hex-character fingerprint of spec 8.4 is 48 bits of a SHA-256 of the DEK. For the random 256-bit DEKs Azure services generate that reveals nothing, but a *short or guessable*
    value sent by a test client could be brute-forced from its fingerprint. EkmMock follows the spec; if that matters, a salted fingerprint (per process) would still let one match wrap input to unwrap output within a run.
29. **Spec 8.3 says `EnableBuffering`; M4 wraps the streams instead.** The reasons are in DECISIONS "M4: Capture pipeline" (no read-ahead before routing/auth, Kestrel's body-size error keeps its M2 mapping, no
    double buffering). Observable differences: none in responses; a rejected request's body is read after the response with a 100 ms bound. If the spec author meant `EnableBuffering` literally (for example to let handlers re-read the
    body), say so; nothing in the code base re-reads a body.
30. **Bodies above 16 KiB are not fully captured, and on a secret position not at all.** A wrap request cannot exceed 16 KiB (Kestrel and the endpoint refuse it), but an *unwrap response* with an A256KW DEK above roughly
    12 KB would exceed 16 KiB of base64url and show as "not captured" (size only). Spec 4.10 gives A256KW no upper DEK size; Azure services use 32-byte DEKs. Raise the capture limit if a real service ever needs it.
31. **TLS session resumption in the inspector.** `Tls.Resumed` is always `false` and the Connections tab's resumption rate is always 0, because M3 disabled resumption (question 23). If resumption is enabled later the
    connection event and the record carry the value without further change.
32. **The 150/250 ms warning/error log levels (spec 9) are not implemented yet** (decided in DECISIONS "M4: Capture pipeline"; M7). Until then a slow request is visible in the inspector (budget colour, filter "only over
    budget") and in the `duration_ms` field, not as a log level.
    - **Status (M7): implemented.** Information up to and including 150 ms, Warning strictly above 150 ms, Error strictly above 250 ms (the `Limits:LatencyWarningMs` / `LatencyBudgetMs` options), proven at the boundaries and end to end; see DECISIONS "M7: Structured log levels".
33. **Docker port mapping versus the mandatory loopback bind check (M5).** Spec 5.4 reaches LoopbackOnly "via docker port mapping `127.0.0.1:8080:8080`", but the app must refuse `LoopbackOnly` with a non-loopback bind, and a
    container needs a non-loopback bind (the mapped traffic arrives on the bridge address) to be reachable at all. Inside a container the console therefore cannot run in LoopbackOnly. Options for M9: require `EntraId` in the image, or add an explicit,
    loudly named opt-in (for example `Console:Auth=LoopbackOnly` plus `Console:ContainerPortMapped=true` that allows the bind but keeps the Host-header and Origin checks). Not decided; the strict rule stays.
    - **Resolved (M9) by a deliberate, narrow deviation; this is a conflict inside the spec (5.4/14 test 17 versus 11.2), not something the spec decided.** The strict refusal is unchanged by default (test 17 still passes everywhere, including in a container).
      One opt-in, the **environment variable** `EKMMOCK_CONSOLE_CONTAINER_PUBLISH=true` (an environment variable like `EKMMOCK_ENABLE_FAULTS`, never a configuration value), allows a non-loopback console bind **only when** the auth mode is `LoopbackOnly` **and** the process is demonstrably in a Linux container
      (`DOTNET_RUNNING_IN_CONTAINER=true` plus `/.dockerenv`, `/run/.containerenv` or `KUBERNETES_SERVICE_HOST`). Set outside a container, or with `EntraId`, it makes the host refuse to start. While active: a startup warning, a banner on every console page
      ("Console bound inside a container, host publish must be loopback-only"), `container_publish` in `/api/console/status`, and a **runtime source-address check** (loopback, RFC 1918, IPv4 link-local, IPv6 ULA and link-local, and their IPv4-mapped forms; everything else gets 403). The Host-header (DNS rebinding) and Origin checks stay. Details and tests: DECISIONS "M9: Container-safe console binding".
    - **Residual risk, stated plainly: the primary control is the host side of the port mapping.** `-p 127.0.0.1:8080:8080` keeps the console on the host's loopback. An operator who publishes `0.0.0.0:8080` exposes an **unauthenticated** console to the whole network segment: the source check only blocks public source addresses, and a LAN peer is a private address.
      The compose files hard-code `127.0.0.1` in front of the console port and say why in a comment; a static test fails if that mapping changes. Use `EntraId` for any console that must be reachable from another machine.
    - Not verified: which exact source address the container sees for a connection published on host loopback (it depends on the engine: the bridge gateway `172.x` on a Linux engine, a NAT address on Docker Desktop). All of them are private; connections through `127.0.0.1:<port>` were served in the M9 runs, a request with a forged `Host` header got 403.
34. **Entra sign-in is not verified against a real tenant (M5).** The OIDC handshake (Microsoft.Identity.Web, cookie, sign-out) could not be run offline. Verified instead: policy enforcement (allowed object id ok, other id 403, anonymous challenged),
    group-claim matching, tenant check and the start-up validation matrix, using a fake authentication scheme. Needs a manual check with a real app registration (redirect URI `https://<console host>/signin-oidc`).
35. **Group-claim overage (M5).** With more than about 200 groups Entra sends a Graph link instead of the `groups` claim; `AllowedGroupId` then denies. Use `AllowedObjectIds` or "groups assigned to the application" for such users.
    Resolving the overage through Graph was not implemented.
36. **Circuit identity is not revalidated (M5).** A signed-in user keeps their circuit after removal from the allow-list until the circuit ends or the sign-in cookie expires. Acceptable for a test tool; say so if it is not.
37. **Fluent UI Blazor v4 versus v5 (M5).** v4.14.5 was chosen because the repository skill documents v4. v5.0.1 is the latest stable; migrating later affects `FluentSelect`, theming and some component names.

38. **CLI authentication against `EntraId` (M6).** The CLI-friendly `/api/console/*` mutations accept the `X-EkmMock-Client` header instead of an antiforgery token, but in `EntraId` mode the console still authenticates with the OIDC cookie, which a CLI does not have. M8 must decide between a bearer-token
    scheme (device-code or client-credentials against the app registration) and a short-lived console-issued token. In `LoopbackOnly` the header is the only protection, by design (see DECISIONS "M6: REST API for the CLI"). **Answered in M8** (DECISIONS "M8: Console access from the CLI"): bearer token on `/api/console/*` only, device code in the CLI; verification against a real tenant is open question 53.
39. **Trust import has no file upload (M6).** The Managed HSM JSON/PEM is pasted into a text area; a file picker (`InputFile` with a size cap) was not added. Easy to add if wanted.
40. **The console test CA is per process (M6).** It is regenerated on every start, so outside `--dev` (where it is trusted automatically) the Playground needs the one-click "trust the test CA" after each restart, and the old test CA stays in the namespace trust until replaced (stale test CAs are replaced, not piled up).
    Persisting it (encrypted under the key-store master key) would remove the extra click but puts a client private key on disk.
41. **The generated test root CA of the console cannot re-issue (M6).** (The VM flow can: its CA key lives in `/opt/ekmmock/pki-private`, root-only and not mounted into the container, and `ekmmock-vm.sh reissue` uses it.) Its private key is discarded after signing the server certificate, so renewing means generating a new root and registering the new `root-ca.pem` with the Managed HSM connection. Keeping the CA key encrypted under the master key would allow re-issuing; not done to keep "no private key is ever stored or downloadable" simple.
42. **No real-tenant or Azure verification of the displayed `az` commands (M6).** The `az keyvault key create` / `az keyvault ekm-connection create` strings follow spec 15 and Microsoft Learn but were not run against a Managed HSM.
43. **Per-key self-test cases exist only for keys present at startup (M6).** A key created later is covered by the self-test at the next start (About shows the result of the last run).
44. **Toast placement (M6).** A Fluent toast can overlap the page header in the top-right corner for a few seconds (cosmetic; seen in the visual check). Messages are also shown inline, so nothing is lost.
45. **`Dev:SeedSampleKeys` is not on with `--dev` (M6).** A fresh `--dev` start has `_default` and the console test trust but no keys; the visual check turned the seeding on through the environment. Say so if `--dev` should seed sample keys.
46. **Windows leaks CNG key files from the test run (M6; reduced in M7).** Cause (proven by probes in M7): a TLS certificate whose key SChannel needs is stored as a persisted CNG key file in `%APPDATA%\Microsoft\Crypto\Keys`, and that file is removed **only when the `X509Certificate2` is disposed**
    (not by GC, not at process exit); `EphemeralKeySet` is refused by SChannel for TLS server and client certificates. M7 made the CA certificates ephemeral, disposes the server certificate snapshots and test certificates deterministically, and shares hosts through fixtures. Measured on this machine: **+113 files per full solution run before (baseline copy of the M6 code), +9 per full run now; Server.Tests alone +2**.
    What remains (about 9 per run) comes from processes that are killed rather than stopped (the Playwright tests kill the spawned `--dev` server: about three keys each) and cannot be fixed from inside the process. A Windows-only guard test proves that creating and disposing a CA and its leaves leaves no files. Pre-existing files were never touched. Status: reduced, remaining cause documented; closing it would need a graceful-stop signal for the spawned server in the browser tests.
47. **Occasional flake in `ConsolePortSeparationTests` under heavy load (M6; still open in M7).** The first mutual-TLS handshake of the test class's fixture (`SendSampleTrafficAsync`) is rejected now and then ("The decryption operation failed ... The certificate chain was issued by an authority that is not trusted"); all theory cases of the class then fail. On the client this message is the server's `unknown_ca` alert, so the
    server-side `ClientCertificateValidator` said "not trusted" for a freshly issued client certificate. Frequency in M7: 3 of 21 full-solution runs (series of five: 0, 1, 2, 0 occurrences, then 0 in a final single run), always while the Server and Console test projects ran in parallel (once the same run also showed a Chromium `net::ERR_NO_BUFFER_SPACE`, i.e. machine-level socket/buffer pressure); it did **not** reproduce in 6 isolated runs of the class under full CPU load,
    and not seen in the few Server-project-only runs. Checked and ruled out by reading: SKI/AKI are present on every generated certificate, CA names are distinct per host, validity starts 5 minutes in the past, the trust snapshot swap is a compare-and-swap with a 30 s retire grace. Not proven: the Windows chain engine with `CustomRootTrust` failing under system-wide resource pressure. The fixture and the test now report the server's recorded handshake failures
    (reason, description, chain status) in the failure message, so the next occurrence names the cause. No production code change was made for it (nothing indicates a defect in the validator).
48. **What Managed HSM does with 429, 5xx, a blackhole, a closed connection and a slow answer is untested (M7).** The fault kinds exist to find out (retry behaviour, timeouts, whether the key operation is retried, how long Managed HSM waits for a blackhole). Nothing in EkmMock claims a real behaviour; record results in `docs/RESULTS.md` during the end-to-end run.
49. **The injected delay is applied after the deadline checkpoint (M7).** A delayed request is still answered (and counted in `ekmmock_budget_exceeded_total`), because the delay stands for a remote HSM round trip. Say so if a delay should instead be subject to the 200 ms internal deadline (it would then answer 429 and the spec 14 test 26 scenario would change).
50. **`ekmmock_budget_exceeded_total` counts the internal deadline, not the 250 ms colour (M7).** A 300 ms request with a 5 s deadline is red in the console and in the log but not counted. Say so if the metric should follow the 250 ms budget instead.
51. **Faults answer before authentication (M7).** HSM offline, error rate and close connection are decided before Auth, so an anonymous caller sees 503/429/500 or a reset instead of 401; blackhole, delay and key-disabled apply only to authenticated callers (they need a slot or the key). Say so if every fault should wait for Auth.
52. **.NET `HttpClient` can surface an early response only after it finished sending the body (M7).** The slow-body/deadline tests therefore assert on the server-side record rather than on the client's elapsed time. This is a client behaviour, not a server one.
53. **The Entra bearer path of the console API is not verified against a real tenant (M8; extends question 38, which is answered by design).** `/api/console/*` accepts a bearer token in `EntraId` mode and the CLI signs in with a device code, but both were tested only with locally signed JWTs (a fake validation setup) and a fake credential. Needed in a real tenant: the app registration must allow public client flows (device code), expose an API scope (the CLI asks for `api://<client-id>/.default`), and issue tokens with an `scp` or `roles` claim (Identity.Web rejects tokens with neither); the signed-in object id or group must be in the console's allow list.
    Untested: consent prompts, conditional access with device code, token lifetime for long conformance runs (the token is held in memory only, no refresh cache by design).
54. **Log lines can be dropped under extreme overload (M8).** The console logger uses `QueueFullMode=DropWrite` (queue 16,384 lines) so that request threads never wait for stdout (waiting cost an order of magnitude of throughput in the benchmark). Under a sustained overload the oldest guarantee "every request is logged" does not hold for the stdout log (the inspector and metrics are independent). Say so if the log must be lossless (then use a file/sink with back-pressure and accept the latency).
55. **~10 s periodic stalls of 100-340 ms at about 30k req/s (M8, not root-caused).** Closed-loop p99 targets are met, but 0.001-0.003 % of the requests take 250-340 ms (in one cluster of all workers about every 10 s); open loop at 5,000 req/s shows p99 36 ms. GC pause counters spike with the stalls. Ruled out by experiment: logging, inspector ring size, key store flush, tiered compilation/PGO, gen0 budget, concurrent GC; workstation GC improves the open-loop p99 but lowers closed-loop throughput. Leading suspect: client and server on the same 8 CPUs.
    Re-measure with the client on another machine (M9, Azure) before changing anything else.
56. **The generated test PKI pollutes the Windows certificate store and CNG key folder (M8).** `ekmmock certs` and the CLI tests create certificates whose keys SChannel persists (as in question 46); the CLI disposes what it can, a killed process leaks files. `certs` output is for tests only and says so.
57. **`--persistence-state` is a two-phase test (M8).** A single run cannot restart the server, so test 14.13 passes only when the suite is run twice around a restart (phase 1 saves a key, namespace and a wrapped DEK to the state file, phase 2 verifies them and cleans up); in a one-shot run it SKIPs with that reason. The state file holds a wrapped DEK and the DEK's SHA-256 (synthetic data), never key material.
58. **Windows ACL for owner-only files (M8).** `init` and `certs` create secret files with an ACL for the current user only (set at creation). It is tested by reading the ACL back; it was not tested for domain accounts, roaming profiles or network shares. On Unix the mode is 600 at creation.
59. **The CLI has no disk token cache for device-code sign-in (M8, by design).** Each CLI call signs in again unless `EKMMOCK_CONSOLE_TOKEN` carries a token (for example from `az account get-access-token`). Say so if a persisted, encrypted cache is wanted.
60. **A fresh `--dev` still has no sample keys (M8; was 45).** The benchmark and the CLI tests set `Dev__SeedSampleKeys=true` (or create keys with `ekmmock key create`); `--dev` alone creates only `_default` and the console test trust.
    - **Status (M9):** the dev compose file sets `Dev__SeedSampleKeys=true`, so `aes-key-1` and `rsa-key-1` exist there. A plain `--dev` is still without keys.

## Added during M9 (1/2)

61. **The container image cannot be built from nuget.org on the network this was developed on (M9).** `docker build` fails with `NU1301` (`SSL handshake failure` towards `api.nuget.org`, reproducible with `curl` and with `--dns 8.8.8.8`; the same Docker engine reaches `mcr.microsoft.com`, `github.com` and the corporate NuGet mirror). The Dockerfile therefore has `ARG NUGET_SOURCE` (empty by default = the SDK image's nuget.org, the clean-network path); with the mirror as `NUGET_SOURCE` the image builds.
    **The standard path (`docker build -f deploy/docker/Dockerfile .` with no argument) was NOT built successfully on the development machine.** It **was** built successfully by the CI `image-conformance` job on a GitHub runner (nuget.org reachable; run 42713960603), and that image passed the conformance suite. See DECISIONS "M9: Docker build and restore".
62. **The health check does not verify the console certificate (M9).** `HEALTHCHECK` runs `ekmmock health --insecure-console-cert` against `https://127.0.0.1:8080` inside the container (the M8 loopback-only escape hatch). The probe cannot be intercepted (same network namespace) and `/healthz` answers only `{"status":"alive"}`, but it does not prove which certificate the console serves. Pinning would need the thumbprint at build time (impossible: certificates are runtime data); `--console-ca`/`--console-pin` exist for a probe that knows them.
63. **Data Protection keys are unencrypted files on the data volume (M9).** The console's antiforgery and sign-in-cookie keys are stored in `/data/dataprotection` (mode 600, owner `app`), without an XML encryptor (ASP.NET Core logs a warning at every start). Anyone who can read the volume can already read the encrypted key store, and these keys only forge console tokens, but a leaked volume backup therefore also allows forging antiforgery tokens. (Security review follow-up: on ACI the same holds for anyone who holds the storage account key, see 79.) Encrypting them under the master key would be possible; not done.
    They survive a restart (open consoles stay valid); without a writable volume they are in memory and tokens die with the process (a warning says so).
64. **Whether the image's R2R, Server GC and `DOTNET_EnableDiagnostics_IPC=0` choices help on the target VM size is not measured (M9).** Idle RSS on an 8-CPU Docker Desktop VM is about 130 MB for both Server GC and workstation GC (measured), which says nothing about a 2-vCPU B2s VM under load. Re-measure there (`ekmmock test bench` against the VM) before tuning `DOTNET_GCHeapCount`/`DOTNET_GCConserveMemory`.
65. **The browser tests in CI install Chromium in their own job (M9).** They need `playwright install --with-deps chromium` (a download from Microsoft's CDN plus apt packages), so they are a separate job: a failed download cannot fail the build, test and image jobs. First CI run: 13 of 13 passed on `ubuntu-latest`. They have not been run on any other Linux image.
66. **No licence is declared (M9).** The repository has no `LICENSE` file, so the image label `org.opencontainers.image.licenses` says `NOASSERTION`. Add the licence to the repository and the label when it is decided.
67. **Source address seen by the container for loopback-published connections is not recorded (M9, see 33).**
68. **Shared-runner timing (M9).** On the GitHub Windows runner one console test (first mutual-TLS handshake in a bUnit test) exceeded a 5 s wait once; the wait is now 20 s. The inspector overhead benchmark (p99 < 1 ms) passed on both runners, but on shared CI hardware it can fail through noise; if it does, rerun before suspecting the code. (M9 part 2: a Linux job also showed that a test which waits for "the next connection event after a mark" can pick up a late event of an earlier test; `Linux_AClientOfferingOnlyAes128_...` now selects its event by the client port. Other tests that use `NextEventAsync` without a connection filter after a test that does not wait for its own event could behave the same way.)
69. **`docker compose up --wait` is not used (M9).** Some Compose versions treat an exited one-shot container as an error with `--wait` (seen on the GitHub runner; Compose 5.6.1 locally accepts it). The make target and the PowerShell script wait explicitly instead.

## Added during M9 (2/2)

70. **Spec and Learn quickstart say `EkmProxyOperation`; the Learn logging article never uses that name.** Spec section 9/15 and the Learn quickstart ("View audit logs": "Every EKM Proxy call produces an `EkmProxyOperation` entry in your Managed HSM diagnostic logs") speak of an `EkmProxyOperation` record, but the query in the same quickstart and the "Logging and monitoring for Managed HSM external key management" article use the table
    `AzureDiagnostics` with `ResourceProvider == "MICROSOFT.KEYVAULT"` and `OperationName` of `EkmGetProxyInfo`, `EkmGetKeyMetadata`, `EkmWrapKey` or `EkmUnwrapKey` (the logging article lists exactly these four). `EkmProxyOperation` is not a value anywhere in the queries. The RUNBOOK, `e2e.sh` and the inspector's `KqlSnippets` use the four real operation names.
    The category to enable on the Managed HSM diagnostic setting is **AuditEvent**. Confirm with real rows whether any record is literally named `EkmProxyOperation`.
71. **`az keyvault ekm-connection`: availability, syntax and discrepancies (checked with `--help` of Azure CLI 2.92.0, not run against Azure).** The group exists in the core CLI (no extension needed here) with `create`, `check`, `show`, `update`, `delete` and `certificate show`. It matches the spec: `create --hsm-name --host --server-ca-certificate [--path-prefix]`, `check --hsm-name`, `certificate show --hsm-name`, `delete --hsm-name`; `key create --external-key-id` exists too.
    Differences and additions: (a) `--path-prefix` must start with `/`; (b) `--host` accepts `FQDN` or `FQDN:port` (default 443; Learn says only 443 is supported); (c) `--server-ca-certificate` takes a PEM chain file or several files (PEM or DER); (d) there is a `--server-cn/--server-subject-common-name` option (for the Private Link name, not in the spec); (e) Learn's troubleshooting page runs `az keyvault ekm-connection list`, which 2.92.0 does **not** have (`show` is used instead);
    (f) the Learn quickstart's AES `wrapkey` example uses `A256KW` (as the spec and `e2e.sh` do) and says RSA-OAEP-256 for RSA. Learn's `check` example output shows `"apiVersion": "1.0"` (open question 1). The role names `Managed HSM EKM Administrator` and `Managed HSM Crypto User` come from Learn; the shape of `az keyvault role definition list` / `assignment list` output that `e2e.sh prereqs` queries is assumed (best effort, warnings only).
72. **The VM boot flow was never run (M9 part 2).** `vm.bicep` was built and linted and the cloud-init document renders and parses; `vm-setup.sh` passes `bash -n` and shellcheck and its helpers ran in a shell. Not run on a fresh Ubuntu 24.04 VM: the apt-based Docker install (including the key fingerprint check, which was verified against the live key file), `docker build` of the image on a 2-vCPU B2s (a few minutes, needs nuget.org), `ekmmock certs` from the image on first boot, the bind-mounted master key readable by uid 1654, and the container reaching `ready`.
    Also unverified: that `Standard_B2s` is available in the chosen region, and that a private registry login works. The master key also exists in the root-only cloud-init and Azure agent copies of the custom data on the OS disk (a documented residual copy, not scrubbed: scrubbing platform files could break the agent, and root on the VM can read the key file anyway).
73. **ACI (M9 part 2; extends question 6).** Unverified in Azure: (a) the non-root user binding 443 (`Permission denied` fallback: VM, or `runAsRoot=true`); (b) whether ACI honours `securityContext.runAsUser`/`runAsGroup` outside confidential containers (the Bicep type allows it; the service behaviour is unknown); (c) the Azure Files SMB mount: ownership and `chmod` for uid 1654 (the key store and the Data Protection keys set file modes, which may fail on SMB), and
    file-lock/atomic-rename behaviour of the key store writes on SMB; (d) that a secret volume's files are readable by a non-root user; (e) the Entra sign-in on `https://<fqdn>:8443` with a certificate whose SAN is the container FQDN. Known by design: no read-only root file system, no capability drop, no NSG on the group's public IP, the console is internet-facing behind Entra ID, a read-only certificate volume (renew by redeploying),
    and the legacy DNS label scope (needed so that the FQDN, hence the certificate SAN, is known before the deployment; the secure scopes add a hash). The EKM listener port is a template constant (443); the console port is a parameter (default 8443).
74. **`e2e.sh` was never run against a real Managed HSM (M9 part 2).** Verified: `bash -n`, shellcheck, `--dry-run` of every command, and the local logic (body files, base64url, fingerprints, comparison, failure exit code, deletion of plaintext files) against a test double of `az`. Not verified: every call to Azure and to the console through the tunnel, the role check, `az rest` output (`--query value --output tsv`), how Managed HSM reports a 403/404/429/blackhole, and the length of the 1,000-call baseline (each call starts an `az` process, so client wall time says nothing about proxy latency).
    The script is written so that a result is recorded only by measurement: each scenario appends a snippet to `e2e-work/results/`, and `docs/RESULTS.md` section 3 keeps `NOT YET MEASURED` until then.
75. **`DurationMs` may be empty or may not include the external HSM call (Learn).** The "Measure latency distribution" query in the logging article says that if `DurationMs` is not populated in the workspace, correlate with proxy logs instead, and that proxy logs capture end-to-end latency "including the external HSM call that `DurationMs` doesn't include". The baseline comparison of spec 15 (Azure-side latency versus EkmMock server time) may therefore not be possible with `DurationMs` alone: the difference may need the proxy-side time from the inspector export.
76. **Bicep API versions are those of the Bicep 0.42.1 type library (M9 part 2).** Network 2025-05-01, compute 2025-04-01, Azure Container Instances 2025-09-01, storage 2025-01-01: the newest the linter's `use-recent-api-versions` rule accepts. A newer GA version may exist in Azure that this Bicep version does not know. The CI job installs the *latest* Bicep through `az bicep install`, so a later Bicep release can turn the zero-warning check red (new analyzer rules or an API version that has aged past the rule's 730 days): then upgrade the API version or the rule level in `deploy/azure/bicepconfig.json`.

77. **The root cause of the intermittent Windows finding of M3 is still unproven (security review follow-up M1).** In 2 of 15 full-suite runs on Windows during M3 a request that carried no client certificate was authorized as the test client identity (`200/404` instead of `401`); it was never reproduced, and disabling TLS session resumption (the only mechanism that fitted) was never shown to be the cause. The identity cross-check of the authorizer now **fails closed** (a TLS request whose connection is unknown to the registry, whose handshake is not complete, or whose certificate is not the one the handshake-time validation callback accepted is a 401), so such an event cannot authorize a caller any more; it does not explain the original observation. If a `200/404` without a certificate ever shows up again, the `auth_failure` field of the exchange log line and of the inspector record names the check that refused or (if it still happens) did not. See DECISIONS "Security review follow-up".
78. **The inspector's memory figure is an estimate (security review follow-up M2).** `Inspector:MaxBytes` bounds the sum of `ExchangeRecordSize.Estimate` (strings at two bytes per character, header and masked-field overheads, a fixed 1 KiB per record, retained raw bodies). It ignores the CLR object layout, the pretty-printed JSON that is created lazily for a record somebody opens in the console, the connection event store (2 000 small events), the dashboard samples (separately bounded) and the JSONL writer buffer, so the process can use more than the cap plus the base footprint. The capture queue and the live-feed subscriptions are bounded by count only; their documented worst case at the defaults is about 120 MiB beyond the ring buffer (DECISIONS). A byte bound for the queue was not added: the consumer drains it in microseconds per record and the per-record caps already bound each entry.
79. **ACI: whoever holds the storage account key can forge console cookies (security review follow-up L8; extends 63).** The Azure Files share that holds `/data` is mounted with the account key, and the account must allow shared-key access for that. The ASP.NET Data Protection key ring on that share is unencrypted, so a holder of the key can read it and mint a valid console session cookie (the key store blobs stay encrypted under the master key). No network deny rule was added because ACI cannot be named in a storage firewall without a VNet and a deny would break the mount. Mitigation is procedural (limit who can read the key, rotate it, prefer the VM) or a later VNet-integrated variant. Whether `az storage account keys renew` followed by a redeploy remounts cleanly was not tried.