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
6. ACI: can the non-root container user bind port 443 (no port remapping in ACI)? If not, document the fallback (VM, or root in
   ACI only).
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

**Learn comparison (M2):** no conflict between the implemented contract and the Learn "EKM Proxy API reference" was found; see `DECISIONS.md`
"M2: Learn comparison". Learn's `info` example shows `"api_version": "1.0"` (open question 1) and its 403 row mentions "the operation isn't
supported" (`OperationNotAllowed` exists in the code but nothing emits it yet).
