# Open questions

Seeded from spec section 17. If the Microsoft Learn EKM Proxy API reference conflicts with the spec, add the discrepancy here
and stop the affected work.

1. `api_version` in the `info` response: documented API version is `0.1-preview`, Learn examples show `"1.0"`. Confirm what
   `az keyvault ekm-connection check` accepts (watch it in the inspector).
2. Does Managed HSM send padded or unpadded base64url? EkmMock accepts both; confirm from captured traffic.
3. Should a disabled key still return metadata (current choice: yes)?
4. Which `alg` values and DEK sizes do Azure services (for example Storage) actually send for RSA vs AES external keys?
5. Does Managed HSM use HTTP/1.1 or HTTP/2, and how many connections does it keep open and reuse?
6. ACI: can the non-root container user bind port 443 (no port remapping in ACI)? If not, document the fallback (VM, or root in
   ACI only).
7. Does `System.Buffers.Text.Base64Url` decoding accept padding in the .NET version used? If not, normalise before decoding.
   - **Status:** open. This belongs to M2 (base64url is not part of `EkmMock.Crypto`).
8. Does the .NET version used ship an AES Key Wrap API (Section 6.4)?
   - **Status:** answered in M1. .NET 10.0.14 ships a public API for **RFC 5649 key wrap with padding only**
     (`Aes.EncryptKeyWrapPadded`, `DecryptKeyWrapPadded`, `TryDecryptKeyWrapPadded`, `GetKeyWrapPaddedLength`). RFC 3394 plain key
     wrap (A256KW) exists only as non-public helpers. Decision: A256KWP uses the runtime API, A256KW is implemented in
     `AesKeyWrap.cs`, and an own RFC 5649 implementation is kept as a test and self-test cross-check. See `DECISIONS.md`; a test
     pins the finding so a future .NET that adds a public RFC 3394 API is noticed.
