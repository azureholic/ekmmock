# Open questions

Seeded from spec section 17. If the Microsoft Learn EKM Proxy API reference conflicts with the spec, add the discrepancy here
and stop the affected work.

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
33. **Docker port mapping versus the mandatory loopback bind check (M5).** Spec 5.4 reaches LoopbackOnly "via docker port mapping `127.0.0.1:8080:8080`", but the app must refuse `LoopbackOnly` with a non-loopback bind, and a
    container needs a non-loopback bind (the mapped traffic arrives on the bridge address) to be reachable at all. Inside a container the console therefore cannot run in LoopbackOnly. Options for M9: require `EntraId` in the image, or add an explicit,
    loudly named opt-in (for example `Console:Auth=LoopbackOnly` plus `Console:ContainerPortMapped=true` that allows the bind but keeps the Host-header and Origin checks). Not decided; the strict rule stays.
34. **Entra sign-in is not verified against a real tenant (M5).** The OIDC handshake (Microsoft.Identity.Web, cookie, sign-out) could not be run offline. Verified instead: policy enforcement (allowed object id ok, other id 403, anonymous challenged),
    group-claim matching, tenant check and the start-up validation matrix, using a fake authentication scheme. Needs a manual check with a real app registration (redirect URI `https://<console host>/signin-oidc`).
35. **Group-claim overage (M5).** With more than about 200 groups Entra sends a Graph link instead of the `groups` claim; `AllowedGroupId` then denies. Use `AllowedObjectIds` or "groups assigned to the application" for such users.
    Resolving the overage through Graph was not implemented.
36. **Circuit identity is not revalidated (M5).** A signed-in user keeps their circuit after removal from the allow-list until the circuit ends or the sign-in cookie expires. Acceptable for a test tool; say so if it is not.
37. **Fluent UI Blazor v4 versus v5 (M5).** v4.14.5 was chosen because the repository skill documents v4. v5.0.1 is the latest stable; migrating later affects `FluentSelect`, theming and some component names.
