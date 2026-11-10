# EkmMock results

This file separates **what was measured in this repository** (section 1 and 2) from **what is still pending against a real Azure Managed HSM** (section 3, a template). Nothing in section 3 has been measured:
every cell of its **Measured** column says `NOT YET MEASURED` (a test enforces that), and the **Expected** column is an expectation from the spec and Microsoft Learn, not a result.

> **EkmMock is a simulator, not an HSM. Never protect real data with it.** The Azure end-to-end test ([`deploy/azure/e2e.sh`](../deploy/azure/e2e.sh)) is **unverified against a real Managed HSM**: it has only been run with `--dry-run`, `bash -n`, shellcheck and against a test double of `az`.

Related: [README](../README.md) · [RUNBOOK](RUNBOOK.md) · [DECISIONS](DECISIONS.md) · [OPEN-QUESTIONS](OPEN-QUESTIONS.md) · [benchmarks](benchmarks/README.md).

## 1. Local verification (measured)

### 1.1 Build and tests

Measured on the development machine (Windows 10.0.26300, Docker Desktop with the Linux engine) on 9 November 2026 (23:47 UTC) on the base commit `2b92c20` plus the working tree of the commit that adds this file (the numbers cannot name their own commit hash; the final report of the milestone does).

| Item | Result |
|---|---|
| `dotnet build EkmMock.sln -warnaserror` | 0 warnings, 0 errors |
| `dotnet test --solution EkmMock.sln` (Windows, Debug, including the Playwright browser tests) | **2,206 tests: 2,202 passed, 0 failed, 4 skipped** (M9 (2/2)). After the [security review follow-up](DECISIONS.md#security-review-follow-up): **2,305 tests: 2,298 passed, 0 failed, 7 skipped** |
| Per project | Crypto 308, Server 1,319, Cli 280, Console 299 (M9). After the follow-up: Crypto 308, Server 1,418, Cli 280, Console 299 |
| The 4 skips | `CipherPolicyTests.Linux_*`: `CipherSuitesPolicy` is not supported by the Windows TLS stack; they run on Linux (container run and CI). The follow-up added 3 skips on Windows: two Unix file-mode tests (`AuditHardeningTests`, `PkiKeyFilePermissionsTests`; they ran and passed in the Linux container) |
| Security review follow-up (Linux container, Server project, `tests/run-server-tests-linux.ps1`) | 1,418 tests, 0 failed, 6 skipped (the 4 Windows-only CNG tests and the 2 `SshSourceRuleTests`, which need the Bicep CLI that the container does not have; the CI `azure-templates` job runs them with `EKMMOCK_REQUIRE_BICEP=true`) |
| Security review follow-up (Server project, 3 consecutive Windows runs) | 1,418 tests, 1,411 passed, 0 failed, 7 skipped, three times |
| Inspector overhead (spec 14 test 24) after the follow-up | p99 28.8 µs masked / 32.3 µs with reveal allowed (threshold 1 ms), see [DECISIONS](DECISIONS.md#security-review-follow-up) |
| Added by M9 (2/2) | 18 tests: `AzureDeploymentFilesTests` (the Azure files) and `DocumentationTests` (links, anchors, this file's matrix and Azure tables); `DeploymentFilesTests` now expects five CI jobs |
| `dotnet list package --vulnerable --include-transitive` | no vulnerable package in any of the 9 projects |
| Before this half (M9 part 1) | 2,188 tests: 2,184 passed, 0 failed, 4 skipped; Linux container run of the Server project 1,301 tests, 0 failed, 4 skipped (the Windows-only CNG tests) |

The Linux run of the new tests happens in CI (not re-run in a local container for this half).

### 1.2 Conformance suite (`ekmmock test conformance`)

Acting as a fake Managed HSM against the real server (mTLS, TLS 1.3): **49 checks: 44 PASS, 0 FAIL, 5 SKIP**, the same result in the compose dev stack, in the GitHub Actions `image-conformance` job and from the host CLI against `dotnet run`.
The 5 skips are the checks that cannot be observed from outside in one run, each with a reason in the report (the suite never skips silently; `ConformanceEndToEndTests` asserts exactly this set):

| Check | Why it is skipped in a one-shot run | Where it is covered instead |
|---|---|---|
| 14.13.a persistence across a restart | One run cannot restart the server; it needs two runs around a restart (`--persistence-state`). | Passes as a two-phase test across a real restart (`PersistenceRestartTests`) and across `docker compose restart` in CI and locally. |
| 14.17.a `LoopbackOnly` with a non-loopback bind refuses to start | Needs to start a server process. | `ConsoleStartupValidationTests` (including a real process). |
| 14.19.a key store at rest holds no raw key bytes | Needs the server's data folder. | `KeyStoreTests`. |
| 14.24.a inspector overhead < 1 ms at p99 | An in-process measurement. | `InspectorOverheadBenchmarkTests`. |
| 14.25.a 60 s benchmark | Takes 60 s; use `ekmmock test bench`. | Section 1.5. |

### 1.3 Container verification (real runs, Docker Desktop, Linux engine)

From [DECISIONS](DECISIONS.md) "M9 container verification"; the image was built from this code (417 MB):

| Check | Result |
|---|---|
| Conformance in the compose dev stack | 44 PASS, 0 FAIL, 5 SKIP; 14.13 two-phase across `docker compose restart`: PASS |
| TLS in the container (OpenSSL client): only `TLS_AES_256_GCM_SHA384` / only `TLS_AES_128_GCM_SHA256` | accepted / accepted |
| only `TLS_CHACHA20_POLY1305_SHA256`; TLS 1.2 | refused (`handshake failure`) / refused (`protocol version`) |
| Hardening | non-root uid 1654; root file system read-only (writes fail); `/data` and tmpfs `/tmp` writable; all capabilities dropped; `NoNewPrivs` |
| Console exposure | published on the host loopback only; a forged `Host` header got 403; console paths on the EKM port and the reverse are 404 |
| Production `compose.yaml` | healthy, `dev_mode=false`, master key from a Docker secret file, graceful stop (0.5 s, exit 0) |
| Non-root bind of 443 (OQ 6) on Docker | works with Docker's default `ip_unprivileged_port_start=0`; denied with the sysctl at 1024 |
| **Not run** | ACI, a Linux host (the Makefile was dry-run only), image scanning |

### 1.4 CI

The last completed GitHub Actions run before this half is [42716589933](https://github.com/azureholic/ekmmock/actions/runs/42716589933) (`push` to `main`, commit `2b92c20`): **success**, all four jobs. Earlier runs of M9 (1/2) are described in [DECISIONS](DECISIONS.md) "CI": the first run found real problems (a Compose `--wait` incompatibility, a test that wrote to `/data`, a slow-runner wait), a later one failed two timing-sensitive tests on the Windows runner ([OQ 68](OPEN-QUESTIONS.md)) and was fixed by running the test assemblies one at a time.
This half adds a fifth job, `azure-templates` (Bicep build and lint, example parameters, shellcheck, `e2e.sh --dry-run`). The result of the run for the commit that adds this file is recorded in the final report of the milestone and, once known, here: **CI result of M9 (2/2):** the first run for this half ([42723835243](https://github.com/azureholic/ekmmock/actions/runs/42723835243), commit `ef0b65e`) had four green jobs, including the new `azure-templates` job, and one red: the Linux job failed `CipherPolicyTests.Linux_AClientOfferingOnlyAes128_NegotiatesAes128_AndTheEventSaysSo`, an existing test that picked up the connection event of the previous test on a slow runner (a test race, fixed by selecting the event by the client port).
The next run ([42725095395](https://github.com/azureholic/ekmmock/actions/runs/42725095395), commit `37bf49e`) is **green: all five jobs** (Linux build/test/vulnerability scan, Windows build/test, browser tests, image build and conformance, Azure templates).

### 1.5 Benchmarks (spec 14 test 25)

Measured with `ekmmock test bench`, Release build, `--dev`, TLS 1.3 + mTLS over loopback, **client and server on the same shared developer machine** (Intel i7-9700K, 8 logical CPUs, Windows 10.0.26300, .NET 10.0.14),
concurrency 16, 60 s measured after a 5 s warm-up, one kept-alive HTTP/1.1 connection per worker, 32-byte DEK, all on 9 November 2026 (UTC). Read from `docs/benchmarks/*.json`:

| Operation | Requests | req/s | p50 | p90 | p99 | max | > 250 ms | Errors | Target (p99) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| AES `unwrapkey` A256KWP | 1,813,291 | 30,221 | 0.41 ms | 0.68 ms | 1.56 ms | 327 ms | 16 | 0 | < 10 ms: met |
| RSA-2048 `unwrapkey` | 562,028 | 9,367 | 1.45 ms | 2.34 ms | 4.32 ms | 340 ms | 16 | 0 | < 30 ms: met |
| RSA-4096 `unwrapkey` | 113,628 | 1,894 | 8.19 ms | 11.9 ms | 18.7 ms | 171 ms | 0 | 0 | < 100 ms: met |
| `info` | 1,957,493 | 32,625 | 0.37 ms | 0.64 ms | 1.62 ms | 315 ms | 16 | 0 | < 5 ms: met |
| AES `unwrapkey`, open loop 1,000 req/s | 60,000 | 1,000 | 0.23 ms | 0.39 ms | 5.47 ms | 116 ms | 0 | 0 | < 10 ms: met |
| AES `unwrapkey`, open loop 5,000 req/s | 300,000 | 5,000 | 0.33 ms | 1.91 ms | 36.4 ms | 89 ms | 0 | 0 | < 10 ms: **not met** (stall-aware measure) |
| (before the M8 fixes) AES `unwrapkey` | 19,908 | 332 | 47.0 ms | 67.6 ms | 101 ms | 290 ms | 1 | 0 | for comparison only |

**Honest reading.** The p99 targets are met in the closed loop. The spec's "0 % over 250 ms" is **not strictly met**: 0.001 % to 0.003 % of the requests (one cluster of 16 at once, about every 10 s) took 100 to 340 ms; the cause is not isolated (leading suspect: client and server on the same 8 CPUs, [OQ 55](OPEN-QUESTIONS.md)).
At 5,000 req/s open loop the AES p99 (36 ms) misses the 10 ms target with nothing over 250 ms. Not measured on the 2-vCPU Azure target or with the client on another machine.

### 1.6 What was validated offline for the Azure artefacts

| Check | Result |
|---|---|
| `bicep build` and `bicep lint` of `vm.bicep` and `aci.bicep` (Bicep 0.42.1, `bicepconfig.json`: recent API versions, secrets) | 0 diagnostics for both |
| `bicep format` | no difference for both templates |
| `bicep build-params` of the two example parameter files (environment values supplied) | pass; this check found placeholders that violated the length decorators |
| `bash -n` of `e2e.sh` and `vm-setup.sh` | pass |
| shellcheck (`koalaman/shellcheck:stable`, `-x -S style`) | clean for both scripts |
| `e2e.sh --dry-run` of every subcommand (and `all` with a path prefix) | commands rendered, nothing executed, nothing written |
| `e2e.sh roundtrip` against a test double of `az` (identity wrap/unwrap) | two PASS lines; a changed unwrap result gives FAIL and exit 1; no plaintext DEK file left; nothing secret-looking in the work folder |
| cloud-init document rendered with the Bicep token set | same token set in YAML and Bicep, the YAML parses, the files decode, the permissions are as designed (a Python script, not part of the repository) |
| `registry_host` and `cfg` of `vm-setup.sh` sourced in a shell | pass |
| Docker apt key fingerprint `9DC858229FC7DD38854AE2D88D81803C0EBFCD88` | read from the live key file with `gpg` and equal |
| `az keyvault ekm-connection create/check/show/update/delete/certificate show --help`, `az keyvault key create --help` (CLI 2.92.0) | the command group and the flags used exist ([OQ 71](OPEN-QUESTIONS.md)) |
| Markdown links and anchors; names in section 2 | `DocumentationTests`, passing |
| Secret scan (private-key headers, long base64, GUIDs, literal Azure host names) over the new files | clean (`AzureDeploymentFilesTests`) |
| `az deployment group validate` / `what-if`, any deployment | **not run**: they need a subscription and an existing resource group; nothing was deployed |

## 2. Spec 14 verification matrix

Every row names the tests that prove it; **the names are checked against the test sources by `DocumentationTests`** (a name that does not exist fails the build). `Class.Method` is an xUnit test; a bare class name is a class of cases.
Status values: `automated-passing` (an xUnit test passed in the runs of section 1.1), `conformance-only` (only the CLI conformance suite proves it), `skipped-explained` (not run in the suite or on a platform, with the reason), `not-verifiable-locally` (needs Azure).
The conformance ids are those of [DECISIONS](DECISIONS.md) "M8: conformance suite"; all 27 tests are covered by at least one xUnit test, and the Azure-side parts are in section 3.

| # | Acceptance test (spec 14) | Proven by (xUnit) | Conformance | Status |
|---|---|---|---|---|
| 1 | `info` returns 200 with all five fields; 503 when "HSM offline" is on | `InfoTests.Info_Returns200WithTheFiveConfiguredFields`, `InfoTests.Info_Returns503HsmUnavailable_WhenTheEngineIsUnavailable` | 14.1.a, 14.1.b | `automated-passing` |
| 2 | Missing or unsupported `api-version` is 400 | `TransportAndValidationTests.MissingOrUnsupportedApiVersion_Returns400UnsupportedApiVersion` | 14.2.a, 14.2.b | `automated-passing` |
| 3 | Key name of 65 characters, or with `_` or `.`, is 400 `InvalidKeyName` | `NamespacePrefixTests.KeyName_FollowsTheSpecPattern`, `KeyLifecycleTests.Create_KeyNameOf65Characters_IsInvalidAnd64IsAccepted`, `KestrelLimitsTests.APercentEncodedSlashInTheKeyName_IsInvalidKeyName_OnRealKestrel` | 14.3.a, 14.3.b | `automated-passing` |
| 4 | Unknown, other-namespace and destroyed keys are 404 | `KeyStateTests.UnknownDestroyedAndOtherNamespaceKeys_Return404KeyNotFound`, `BackendWrapUnwrapTests.KeyInAnotherNamespace_IsKeyNotFound`, `KeyLifecycleTests.DestroyedKey_IsKeyNotFoundEverywhere_AndLeavesATombstone` | 14.4.a, b, c | `automated-passing` |
| 5 | Metadata of AES-256 matches 4.7; RSA `n`, `e` = `AQAB`, no leading zero | `MetadataTests.AesMetadata_MatchesSection47Exactly`, `MetadataTests.RsaMetadata_HasTheRightModulus_AQAB_AndNoLeadingZeroByte` | 14.5.a, 14.5.b | `automated-passing` |
| 6 | Round trip for every algorithm and DEK sizes 16/24/32/64 (KWP 1 to 4096, RSA to its limit) | `BackendWrapUnwrapTests.A256KW_RoundTrip_ForDekSizes`, `BackendWrapUnwrapTests.A256KWP_EveryLengthFrom1To4096_RoundTripsThroughTheEngine`, `BackendWrapUnwrapTests.RsaOaep_AtTheMaximumPlaintextLength_RoundTripsAndOneByteMoreIsInvalidInput`, `WrapUnwrapTests.AesRoundTrip_ForTheStandardDekSizes`, `MtlsEndpointTests.ValidClient_WrapUnwrapRoundTrip_OverMtls_ForAesAndRsa` | 14.6.a to f | `automated-passing` |
| 7 | AES-KW and KWP match the RFC 3394 / 5649 vectors (imported RFC KEK) | `AesKeyWrapTests.Rfc3394_Wrap_MatchesPublishedVector`, `KnownAnswerAndInteropTests.Rfc3394Section4_6_Vector_MatchesOverHttp_WithAnImportedKek`, `KnownAnswerAndInteropTests.A256KWP_KnownAnswer_MatchesOverHttp_FromAnIndependentImplementation` | 14.7.a, 14.7.b (skip when key import is off) | `automated-passing` |
| 8 | RSA-OAEP(-256) interoperates with an independent `RSA` instance, both ways | `BackendWrapUnwrapTests.RsaOaep_EngineWrap_IsDecryptedByAnIndependentRsaInstance`, `BackendWrapUnwrapTests.RsaOaep_IndependentInstanceWrap_IsUnwrappedByTheEngine`, `KnownAnswerAndInteropTests.Rsa_ProxyWrap_DecryptsWithAnIndependentRsaInstance_AndTheReverse` | 14.8.a, 14.8.b | `automated-passing` |
| 9 | Algorithm/key-type mismatch is 400 `UnsupportedAlgorithm` | `BackendWrapUnwrapTests.AesKey_WithRsaAlgorithm_IsUnsupportedAlgorithm`, `BackendWrapUnwrapTests.RsaKey_WithAesAlgorithm_IsUnsupportedAlgorithm` | 14.9.a | `automated-passing` |
| 10 | A tampered wrapped value is 400 `InvalidCiphertext`, not 500 | `BackendWrapUnwrapTests.Unwrap_OfTamperedValue_IsInvalidCiphertext_ForEveryByteOfTheInput` | 14.10.a | `automated-passing` |
| 11 | Disabled key: wrap/unwrap 403 `KeyDisabled`, metadata 200; expired 403 `KeyExpired` | `KeyStateTests.DisabledKey_WrapAndUnwrap403KeyDisabled_MetadataStill200`, `KeyStateTests.ExpiredKey_WrapAndUnwrap403KeyExpired_MetadataStill200`, `KeyLifecycleTests.DisabledKey_RejectsWrapAndUnwrapWithKeyDisabled_ButMetadataStillWorks` | 14.11.a, 14.11.b | `automated-passing` |
| 12 | Padded and unpadded base64url accepted; `+` `/` rejected; output unpadded | `WrapUnwrapTests.PaddedAndUnpaddedInput_AreBothAccepted_AndOutputIsAlwaysUnpadded`, `WrapUnwrapTests.StandardBase64Characters_ArePositivelyRejected_EvenWhenTheBytesWouldDecode`, `Base64UrlTests.OQ7_Runtime_Base64Url_AcceptsPaddedAndUnpaddedInput` | 14.12.a, b, c | `automated-passing` |
| 13 | Keys and namespaces survive a restart; an old wrapped DEK unwraps after it | `KeyStoreTests.KeysAndWrappedDeks_SurviveARestart_ForEveryAlgorithm`, `PersistenceOverHttpTests.KeysNamespacesAndWrappedDeks_SurviveARestart`, `PersistenceRestartTests.KeysNamespacesAndWrappedDeks_SurviveARestartOfTheServer` (the real server restarted) | 14.13.a (SKIP in a one-shot run; two-phase PASS in CI and in compose) | `automated-passing` |
| 14 | TLS 1.2 refused; no client certificate 401; untrusted CA fails the handshake; wrong CN 401; CN of A used on B 401 | `MtlsEndpointTests.Tls12OnlyClient_IsRefused_AndTheVersionReasonIsRecorded`, `MtlsEndpointTests.NoClientCertificate_Is401JsonProxyError_NotATlsFailure_ForEveryOperation`, `MtlsEndpointTests.UntrustedCa_FailsTheHandshake_AndAFailureEventWithAReasonIsRecorded`, `MtlsEndpointTests.TrustedCa_ButWrongCommonName_Is401Unauthenticated`, `MtlsEndpointTests.CertificateValidForNamespaceA_IsRejectedOnNamespaceB_AndTheOtherWayRound`; cipher suites: `CipherPolicyTests.Linux_AClientOfferingOnlyChaCha20_IsRefused_AndRecordedAsNoCommonCipherSuite` | 14.14.a to e | `automated-passing` (the four `CipherPolicyTests.Linux_*` are skipped on Windows and ran on Linux: container run and CI) |
| 15 | A replaced server certificate is served within 60 s, no failed in-flight requests | `ServerCertificateReloadTests.ExistingKeepAliveConnections_AndInFlightRequests_NeverFail_WhileTheCertificateIsSwapped`, `ServerCertificatePollFallbackTests.WhenNoFileEventTriggersAReload_ThePollFindsTheChange` | 14.15.a (needs the replacement certificate inputs) | `automated-passing` |
| 16 | EKM paths on the console port 404; console paths on the EKM port 404 | `ConsolePortSeparationTests.EkmRoutes_AreNotFound_OnTheConsolePort`, `ConsolePortSeparationTests.ConsoleRoutes_AreNotFound_OnTheEkmPort_WithAndWithoutAClientCertificate` | 14.16.a, 14.16.b | `automated-passing` |
| 17 | `LoopbackOnly` with a non-loopback bind: the app refuses to start | `ConsoleStartupValidationTests.TheRealProcess_WithLoopbackOnlyAndAPublicBind_ExitsNonZero_WithAClearMessage_AndNothingListens`, `ConsoleStartupValidationTests.LoopbackOnly_WithAnyOtherBind_IsRefused_AndTheMessageNamesTheAddress` | 14.17.a (always SKIP: needs to start a server) | `automated-passing` (with the documented container-publish opt-in, `ConsoleContainerPublishTests`) |
| 18 | Leak scan: no raw key material in any console response, export, JSONL or log | `AdminLeakScanTests.AfterAFullScenario_NoKeyMaterialAppearsAnywhereTheConsoleCanReach`, `InspectorMaskingEndToEndTests.AfterAFullScenario_NoDek_InAnyAlphabet_IsInTheRingJsonlExportsFeedLogsOrAudit` | 14.18.a | `automated-passing` |
| 19 | Key store holds no raw key bytes; a flipped byte marks `Corrupt`; wrong master key: `info` still works, operations 503 | `KeyStoreTests.KeystoreFile_ContainsNoRawKeyBytes_InAnyEncoding`, `KeyStoreTests.FlippingOneByteOfOneBlob_MarksOnlyThatKeyCorrupt_AndOthersStillLoad`, `KeyStoreTests.WrongMasterKey_MarksEveryKeyCorrupt_ButTheLoaderSucceeds`, `PersistenceOverHttpTests.WithADifferentMasterKey_EveryKeyIs503_ButTheServerRunsAndInfoWorks` | 14.19.a (always SKIP: needs the data folder) | `automated-passing` |
| 20 | Every EKM request (2xx, 4xx incl. 401, 429, 5xx) is in Live traffic within 1 s with bodies | `InspectorCaptureTests.EveryRequest_IncludingTheRejectedOnes_IsCaptured_WithBodiesAndTiming`, `InspectorCaptureTests.ARequest_IsVisibleInTheFeedAndTheQuery_WithinOneSecond`, `LiveUpdateTests.EveryKindOfRequest_ReachesTheScreen_Including401And404_WithinOneSecond` | 14.20.a, 14.20.b | `automated-passing` |
| 21 | A TLS handshake failure is a connection event with a reason | `InspectorMtlsTests.ConnectionEvents_FlowThroughTheInspector_IncludingAHandshakeFailureWithItsReason` | 14.21.a | `automated-passing` |
| 22 | Default masking: length and fingerprint only; wrap-input and unwrap-output fingerprints match | `InspectorMaskingEndToEndTests.WrapInput_AndUnwrapOutput_ShowOnlyLengthAndFingerprint_AndTheFingerprintsMatch` | 14.22.a | `automated-passing` |
| 23 | Reveal impossible without `EKMMOCK_INSPECTOR_ALLOW_REVEAL=true`; each reveal audit-logged | `InspectorRevealTests.WithoutRevealAllowed_RevealIsDenied_NothingIsRetained_AndTheAttemptIsAudited`, `InspectorRevealTests.WhenAllowed_ARevealReturnsTheRawValue_AndEveryRevealIsAuditedBeforeItIsReturned` | 14.23.a | `automated-passing` |
| 24 | Inspector overhead < 1 ms p99; a full channel drops the oldest, counts it, never slows the request | `InspectorOverheadBenchmarkTests.CaptureOverhead_IsUnder1msAtP99_InDefaultMaskedMode`, `InspectorCaptureTests.AFullQueue_DropsTheOldest_CountsIt_AndTheRequestsAreNeverSlowed` | 14.24.a (always SKIP: in-process measurement) | `automated-passing` (timing-sensitive on shared CI hardware, [OQ 68](OPEN-QUESTIONS.md)) |
| 25 | Bench at concurrency 16 for 60 s: p99 < 10 / 30 / 100 ms, **0 % over 250 ms**; record the numbers | none (a 60 s load test): measured with `ekmmock test bench`, section 1.5 and [`benchmarks/`](benchmarks/README.md) | 14.25.a (always SKIP in the suite; use `test bench`) | `skipped-explained`: the p99 targets are met, the "0 % over 250 ms" is **not strictly met** (0.001 % to 0.003 %) |
| 26 | Fault delay 300 ms: the client sees > 250 ms, the budget metric increments, the exchange is red with the fault badge | `FaultInjectionTests.ADelayOf300ms_IsSeenByTheClient_CountsAsBudgetExceeded_AndTheExchangeIsRedWithTheFaultBadge`, `FaultInjectionRealHostTests.ADelayPastTheDeadline_OverRealMtls_IsSlowForTheClient_CountedInTheMetrics_AndRedWithTheBadge` | 14.26.a | `automated-passing` |
| 27 | Concurrency limit exceeded: immediate 429 | `LimitsTests.OverTheConcurrencyLimit_TheAnswerIsAnImmediate429_AndSlotsComeBackWhenRequestsEnd` | 14.27.a (needs `--allow-disruptive` and faults) | `automated-passing` |

Not part of spec 14 and **`not-verifiable-locally`**: everything in section 3 (what a real Managed HSM does), the Entra sign-in against a real tenant ([OQ 34, 53](OPEN-QUESTIONS.md)), ACI, and the VM boot flow.

## 3. Azure end-to-end results (spec 15), pending

**Status: pending.** None of the scenarios below has been run. They are implemented in [`deploy/azure/e2e.sh`](../deploy/azure/e2e.sh) (`prereqs`, `trust`, `connect`, `keys`, `roundtrip`, `baseline`, `sweep`, `key-disable`, `key-destroy`, `offline`, `observe`, `cleanup`), which writes a markdown snippet per scenario to `e2e-work/results/`. Copy the measured values here and replace `NOT YET MEASURED` only with something you measured, with the date.
Expected values are expectations from the spec and Microsoft Learn (read 9 November 2026), **not results**.

### 3.0 Environment

| Item | Recorded |
|---|---|
| Date and operator | NOT YET RECORDED |
| Managed HSM name (no real names in this repository: use `<hsm>`) and region | NOT YET RECORDED |
| EkmMock commit, deployment model (VM or ACI), VM size, region | NOT YET RECORDED |
| Azure CLI version, `keyvault` extension, proxy FQDN (placeholder) | NOT YET RECORDED |
| Network distance between the HSM and the VM (same region?) | NOT YET RECORDED |

### 3.1 The four steps of spec 15

| Step | Expected | Measured |
|---|---|---|
| 1. `az keyvault ekm-connection certificate show` then `ekmmock trust import` | JSON with `caCertificates` and `subjectCommonName`; the import preview shows the CN and each CA | NOT YET MEASURED |
| 2. `az keyvault ekm-connection create --host <fqdn> --server-ca-certificate root-ca.pem` then `check` | `check` succeeds with the five `info` fields; an `info` call arrives in Live traffic (does `check` accept `api_version` `0.1-preview`? [OQ 1](OPEN-QUESTIONS.md)) | NOT YET MEASURED |
| 3. `az keyvault key create --external-key-id aes-key-1` and `rsa-key-1` | A `metadata` call arrives per key reference; the key references are created | NOT YET MEASURED |
| 4. `wrapkey`/`unwrapkey` through Managed HSM with a random 32-byte DEK (A256KW, RSA-OAEP-256; also A256KWP and RSA-OAEP if tried) | The unwrapped DEK equals the original; the fingerprint on the wrapkey request equals the one on the unwrapkey response in the console | NOT YET MEASURED |

### 3.2 Baseline: 1,000 unwraps via Managed HSM

| Metric | Expected | Measured |
|---|---|---|
| Calls succeeded / failed | all 1,000 succeed | NOT YET MEASURED |
| EkmMock server time per unwrap (p50 / p95 / p99, console dashboard or export) | well under 5 ms for AES (the local loopback figure was 0.4 ms p50; the VM is a 2-vCPU B2s: [OQ 64](OPEN-QUESTIONS.md)) | NOT YET MEASURED |
| Azure-side `DurationMs` of `EkmUnwrapKey` (p50 / p95 / p99, KQL in the [RUNBOOK](RUNBOOK.md#7-azure-side-logs-diagnostic-settings-and-kql)) | EkmMock time plus network and Managed HSM overhead, below 250 ms | NOT YET MEASURED |
| Difference Azure side minus EkmMock side | roughly network plus Managed HSM overhead | NOT YET MEASURED |
| Is `DurationMs` populated in `AzureDiagnostics`? (Learn says it may not be) | unknown | NOT YET MEASURED |
| Does `correlation_id` match a `correlationId_g` / `CorrelationId` column? ([OQ 26](OPEN-QUESTIONS.md)) | unknown | NOT YET MEASURED |

### 3.3 Latency sweep

Injected with `POST /api/console/faults` (the CLI presets only cover 100, 200 and 260 ms). The Azure-side budget includes network and Managed HSM overhead, so failures may start **below** 250 ms of injected delay.

| Injected delay | Expected | Measured |
|---|---|---|
| 50 ms | succeeds | NOT YET MEASURED |
| 100 ms | succeeds | NOT YET MEASURED |
| 150 ms | succeeds (amber in the console) | NOT YET MEASURED |
| 200 ms | succeeds, close to the limit (at the 200 ms internal deadline) | NOT YET MEASURED |
| 240 ms | at risk: depends on network plus overhead | NOT YET MEASURED |
| 260 ms | fails (past the 250 ms budget) | NOT YET MEASURED |
| 300 ms | fails | NOT YET MEASURED |
| Where Managed HSM starts failing, and the Azure-side error (`ResultType`, `ResultDescription` of `EkmUnwrapKey`) | around 250 ms; the error text is unknown | NOT YET MEASURED |

### 3.4 Disable key and destroy key

| Scenario | Expected | Measured |
|---|---|---|
| `ekmmock key disable`: unwrap through Managed HSM | fails; EkmMock answers `403 KeyDisabled`; how Managed HSM reports it is unknown | NOT YET MEASURED |
| Key re-enabled: unwrap again | succeeds | NOT YET MEASURED |
| Throw-away key destroyed (`key-destroy`): unwrap | fails; EkmMock answers `404 KeyNotFound` | NOT YET MEASURED |
| Effect on a CMK-protected Storage account when the key is disabled (manual) | reads/writes eventually fail | NOT YET MEASURED |
| How long until the workload is affected (manual) | unknown (depends on the service's key caching) | NOT YET MEASURED |

### 3.5 HSM offline and blackhole

| Scenario | Expected | Measured |
|---|---|---|
| "HSM offline" fault: `az keyvault ekm-connection check` | fails; the proxy answers `503 HsmUnavailable` | NOT YET MEASURED |
| "HSM offline": `EkmProxyAvailability` metric and the console heartbeat | metric falls to 0 (`FailureReason` `ProxyServerError`); the heartbeat stays green because `info` is answered (with 503) | NOT YET MEASURED |
| "HSM offline": unwrap through Managed HSM and effect on a CMK workload (manual) | fails | NOT YET MEASURED |
| Blackhole: `check` duration and result | times out (`ProxyTimeoutError`); how long Managed HSM waits is unknown | NOT YET MEASURED |
| Blackhole: unwrap duration and the Azure-side error | fails after Managed HSM's timeout | NOT YET MEASURED |
| Recovery after clearing the fault: time until `EkmProxyAvailability` is 100 again | within a few probes | NOT YET MEASURED |

### 3.6 What Azure actually sends

From the inspector export (`e2e.sh observe`) and the Connections page; these are the open questions 1 to 5, 10, 11 and 14.

| Question | Expected (spec, Learn) | Measured |
|---|---|---|
| `alg` for an AES external key and for an RSA external key, per service (Storage, others) | A256KW / A256KWP and RSA-OAEP-256 / RSA-OAEP (Learn lists all four); unknown which is used | NOT YET MEASURED |
| DEK sizes per key type and service | 32 bytes for Storage; unknown for others | NOT YET MEASURED |
| HTTP version and ALPN | HTTP/1.1 (the spec requires it to work); h2 possible | NOT YET MEASURED |
| Connection reuse (requests per connection, new handshakes per minute) | connections are reused | NOT YET MEASURED |
| Padded or unpadded base64url in requests | unpadded (Learn's troubleshooting says "no padding"); EkmMock accepts both | NOT YET MEASURED |
| Does `info`, `metadata` always carry a JSON body with `request_context`? | yes | NOT YET MEASURED |
| `Content-Type` value Managed HSM sends (charset?) | `application/json` | NOT YET MEASURED |
| `api_version` accepted by `check` | `0.1-preview` (Learn's example shows `1.0`) | NOT YET MEASURED |
| Probe frequency of `EkmGetProxyInfo` | about 3 calls per minute | NOT YET MEASURED |

### 3.7 Clean-up

| Step | Expected | Measured |
|---|---|---|
| Workloads moved off the key | no dependency left | NOT YET MEASURED |
| `az keyvault key delete` for each reference | deleted (soft-deleted) | NOT YET MEASURED |
| `az keyvault ekm-connection delete` | deleted | NOT YET MEASURED |
| Keys destroyed in EkmMock | tombstones; names reserved | NOT YET MEASURED |
| Resource group deleted (VM, disk, IP, NSG) | everything gone, including the key store and CA key on the disk | NOT YET MEASURED |
