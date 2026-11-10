# EkmMock runbook

Operating guide for an EkmMock that Azure Key Vault Managed HSM uses as its EKM proxy (spec section 9). Read the disclaimer first:

> **EkmMock is a simulator, not an HSM.** Never protect real data with it. Destroying a key, or losing the master key, makes any data protected by it **unrecoverable**.

Related: [README](../README.md) · [Azure deployment](../deploy/azure/README.md) · [RESULTS](RESULTS.md) · [DECISIONS](DECISIONS.md) · [OPEN-QUESTIONS](OPEN-QUESTIONS.md).
Everything about how a **real** Managed HSM behaves is **not verified yet**; where this runbook describes Azure-side behaviour it quotes Microsoft Learn (read 9 November 2026) and says so.

## Contents

1. [Daily operations](#1-daily-operations) · 2. [Start, stop, upgrade, backup](#2-start-stop-upgrade-and-back-up) · 3. [Master key custody](#3-master-key-custody-and-backup)
4. [Server certificate renewal](#4-server-certificate-renewal-and-hot-reload) · 5. [Trust after Microsoft rotates the client certificate](#5-trust-management-after-microsoft-rotates-the-client-certificate)
6. [Reading Live traffic and Connections](#6-reading-live-traffic-and-connections-for-common-failures) · 7. [Azure-side logs: diagnostic settings and KQL](#7-azure-side-logs-diagnostic-settings-and-kql)
8. [Correlating `correlation_id`](#8-correlating-the-consoles-correlation_id-with-azure-side-entries) · 9. [Latency-budget triage](#9-latency-budget-triage-150-and-250-ms) · 10. [Fault-injection playbook](#10-fault-injection-playbook)
11. [Metrics and Prometheus](#11-metrics-and-prometheus) · 12. [VM, container and ACI operations](#12-vm-container-and-aci-operations) · 13. [Troubleshooting matrix](#13-troubleshooting-matrix) · 14. [Clean-up order and destructive actions](#14-clean-up-order-and-destructive-actions)

## 1. Daily operations

- **Heartbeat.** The console's Dashboard shows "last `info` call N s ago from CN ...". Managed HSM probes `info` about three times a minute; it is **red after 60 s without a probe**. A red heartbeat means Managed HSM cannot reach the proxy (or the connection was deleted).
- **Live traffic** (start page) shows every call, newest first: green < 150 ms, amber 150 to 250 ms, red > 250 ms. Use the filters "only errors", "only over budget" and "hide health probes".
- **Certificate expiry.** The Certificates page warns 30 days before the server certificate expires. A generated test server certificate is valid for **397 days** (the CA for 3,650): put the date in your calendar.
- **Fault banner.** If a banner says faults are active, somebody injected a fault; clear it (Fault injection page, or `ekmmock faults clear`) before judging any latency or error.
- **Azure side.** Watch the `EkmProxyAvailability` metric of the Managed HSM and the `EkmWrapKey`/`EkmUnwrapKey` records (section 7). Microsoft's published alerts: p95 `DurationMs` above 250 ms over 5 minutes, any authentication failure, more than 1 % failing operations over 5 minutes, client-certificate expiry 30 days ahead, three or more 504-class errors within a minute.

## 2. Start, stop, upgrade and back up

| Task | VM ([`vm.bicep`](../deploy/azure/vm.bicep)) | Docker Compose ([`deploy/docker/compose.yaml`](../deploy/docker/compose.yaml)) |
|---|---|---|
| Status | `ssh <vm> 'sudo /opt/ekmmock/bin/ekmmock-vm.sh status'` (container state, served certificate) and `sudo docker ps` | `docker compose -f deploy/docker/compose.yaml ps` |
| Logs (JSON, one line per request) | `sudo docker logs --tail 100 -f ekmmock` | `docker compose logs -f ekmmock` |
| Restart | `sudo docker restart ekmmock` (the restart policy is `unless-stopped`: it also comes back after a reboot) | `docker compose restart ekmmock` |
| Stop | `sudo docker stop ekmmock` (SIGTERM, graceful) | `docker compose stop ekmmock` |
| Upgrade | `sudo /opt/ekmmock/bin/ekmmock-vm.sh upgrade` rebuilds (or pulls) the image from the configured `repoRef` / `containerImage` and recreates the container; keys, namespaces and certificates are on `/opt/ekmmock/data` and survive | `docker compose up -d --build` |
| Re-create with a changed setting | edit `/opt/ekmmock/config/*` then `sudo /opt/ekmmock/bin/ekmmock-vm.sh run` | change the compose file or environment, `docker compose up -d` |
| First-boot log | `/var/log/ekmmock-bootstrap.log` | |

A restart takes the endpoint down for a few seconds; Managed HSM sees failing probes meanwhile (`EkmProxyAvailability` dips). **Do not restart during a test you want to measure.**

**Data volume backup.** `/opt/ekmmock/data` (VM) or the `ekmmock-data` volume holds `keystore.json` (encrypted keys), `namespaces.json`, the audit log and the certificates (the **VM's test CA private key is not there**: it is in `/opt/ekmmock/pki-private/root-ca.key`, root-only; back that file up separately if you want to be able to re-issue the server certificate under the same root). Stop the container, copy the folder, start it again (or take a disk snapshot).
**A copy of `keystore.json` is useless without the master key, and the master key must not be stored next to it** (section 3). Azure-side note (Learn): Managed HSM does **not** support backup/restore of *external key references*; to recover one, recreate it. EkmMock's own volume is independent of that.

## 3. Master key custody and backup

The Key Store Master Key (KSMK, 32 random bytes, base64) encrypts every key blob (AES-256-GCM). **If it is lost, every key in the store is unrecoverable, and so is every DEK Azure wrapped with it.** If it is wrong, every key loads as `Corrupt` and wrap/unwrap answer `503 HsmUnavailable` while `info` still works.

- **Where it is.** VM: `/opt/ekmmock/secrets/master.key` (mode 0400, readable by the container user, bind-mounted read-only at `/run/secrets/ekmmock_master_key`). Compose: the Docker secret file. ACI: the `EKMMOCK_MASTER_KEY` secure environment variable. Dev: `out/dev/data/master.key`.
- **Back it up on purpose, away from the VM**, before the first key is used: a password manager or a Key Vault secret with access limited to the people who may restore it. You generated it yourself (`openssl rand -base64 32` or `ekmmock init`); deployment templates take it as a secure parameter and never output it.
- **Verify a copy** without exposing it: compare fingerprints, for example `printf %s "$(cat master.key)" | openssl dgst -sha256` on both sides.
- **Who can read it.** Root on the VM, anyone with Azure RBAC rights to run commands on the VM, and anyone with a snapshot of its OS disk (cloud-init and the Azure agent keep a root-only copy of the custom data). Treat these rights as access to the master key.
- **Not supported:** master-key rotation (re-encrypting the store under a new key). The only way to "rotate" is to create new keys under a new store and re-register them, which orphans data protected by the old ones. `ekmmock init --force` refuses to replace a master key while a key store exists, for exactly this reason.
- `--dev` generates a **throw-away** master key (red banner): its keys are unreadable after a restart without it. Never use `--dev` for anything you want to keep.

## 4. Server certificate renewal and hot reload

The server certificate's **SAN must equal the FQDN** registered with `--host` (public-internet model). Managed HSM validates it against the root CA you registered with `--server-ca-certificate`.

- **Same root CA (the usual case):** replace the files and nothing changes on the Managed HSM connection. The server **hot-reloads** a new certificate/key pair within 60 s (file watcher plus a 60 s poll), without dropping connections; or upload it on the console's Certificates page. A bad replacement (expired, no `serverAuth`, key mismatch) is rejected and the old certificate keeps serving; the About and Certificates pages show the error.
- **A different root CA:** update the Managed HSM connection **first**, with a PEM containing the old and the new root, then deploy the new certificate (Learn: this avoids a window where the proxy presents a certificate Managed HSM cannot validate):

  ```bash
  cat old-root.pem new-root.pem > old-and-new-roots.pem
  az keyvault ekm-connection update --hsm-name <hsm> --server-ca-certificate old-and-new-roots.pem
  ```

- **Re-issuing a test certificate on the VM** under the same root. The root CA **private key** is kept in `/opt/ekmmock/pki-private/root-ca.key` (root-owned, mode 0400) and is deliberately **not** under `/opt/ekmmock/data`, which is mounted into (and readable by) the container. One command does it: it copies the CA key into a private scratch folder, issues the certificate for the FQDN (plus `localhost` and `127.0.0.1`), installs it into `/opt/ekmmock/data/tls`, shreds the scratch folder and restarts the container:

  ```bash
  sudo /opt/ekmmock/bin/ekmmock-vm.sh reissue
  ```

  If `/opt/ekmmock/pki-private/root-ca.key` was deleted there is nothing to issue under: a new certificate then needs a new root, and the connection's root CA must be updated first (the "different root CA" case above). A VM created by an earlier version of the template has the key in `/opt/ekmmock/data/pki`; `ekmmock-vm.sh run`, `upgrade` or `reissue` moves it out once.

  The console's own "generate test PKI" button makes a **new root** whose key is discarded: use it only if you are going to update the connection's root CA.
- Check what is served: `echo | openssl s_client -connect <fqdn>:443 -tls1_3 2>/dev/null | openssl x509 -noout -subject -enddate -ext subjectAltName` (without a client certificate the handshake still completes; every operation answers 401).

## 5. Trust management after Microsoft rotates the client certificate

Managed HSM presents a pool-specific client certificate that **Microsoft issues and rotates**. EkmMock trusts by **subject CN plus root CA**, not by fingerprint, so a rotation changes nothing while `subjectCommonName` and `caCertificates` stay the same (Learn: "Configure networking and mTLS").

1. On a schedule (weekly is Learn's suggestion): `az keyvault ekm-connection certificate show --hsm-name <hsm> > mhsm-client.json` and compare `caCertificates` and `subjectCommonName` with what you trusted.
2. If they changed: `ekmmock trust import --ns <namespace> --json mhsm-client.json --dry-run` (shows the CN and each CA's subject, issuer and expiry and any warning), then without `--dry-run`. `--mode merge` (default) adds to the existing trust, `--mode replace` makes the import the trust. Or paste the JSON on the Namespaces & trust page.
3. A `401 Unauthenticated` on every operation, with a client certificate present, right after a rotation is the symptom of a stale trust (Learn lists this as the commonest cause).

## 6. Reading Live traffic and Connections for common failures

**Handshake failures never become HTTP requests.** They appear on the Connections page (and inline in Live traffic when the toggle is on) as a connection event with a reason, and in `ekmmock_tls_handshake_failures_total{reason}`.

| Reason label | What it means | Typical cause | What to do |
|---|---|---|---|
| `client_cert_not_trusted` | The client certificate does not chain to a root CA of **any** namespace. | Managed HSM's CA is not imported, wrong namespace, or the CA was rotated. | Section 5: `az keyvault ekm-connection certificate show`, then `ekmmock trust import`. |
| `tls_version_not_supported` | The client did not offer TLS 1.3 (the detail says what it offered, for example "client offered TLS 1.2"). | A client or test tool that speaks TLS 1.2. Managed HSM requires TLS 1.3. | Fix the client. EkmMock is TLS 1.3 only by design. |
| `no_common_cipher_suite` | TLS 1.3 was offered, but neither `TLS_AES_256_GCM_SHA384` nor `TLS_AES_128_GCM_SHA256`. | A client restricted to ChaCha20. | Fix the client. |
| `cipher_suite_not_allowed` | The handshake completed with another suite (Windows only: the post-handshake policy). | Only on Windows (SChannel). | Run on Linux. |
| `not_tls` | The first bytes were not a TLS handshake. | Plain HTTP to the TLS port, a port scan. | Usually ignore; check what is calling. |
| `handshake_timeout` / `client_closed` | The client never completed the hello, or went away. | A port probe, a firewall dropping packets, a slow client. | Compare with NSG and client logs. |
| `other` | Not classifiable from what the client offered. | Server-side problem (unusable server key), or a hello split over several records. | Check the server log and the certificate. |

**Requests that arrive** (HTTP level, the ProxyError `code` is in the Response tab):

| What you see | Meaning | Fix |
|---|---|---|
| `401 Unauthenticated`, client certificate **absent** | The request reached the app without a client certificate (EkmMock allows that handshake so that the JSON 401 can be returned). | The caller is not Managed HSM (a browser, a scanner), or Managed HSM did not send one. |
| `401`, certificate present, **CN allowed? no** | Wrong subject CN for this namespace. | Import the Managed HSM identity into this namespace (`subjectCommonName` from `certificate show`). |
| `401`, chain result not `NoError` | The chain does not build to this namespace's roots (but another namespace's root accepted it at the handshake). | Trust is per namespace: check the path prefix and the namespace. |
| `401` after a CN allowed on namespace A is used on B | Namespaces are separate trust domains. | Use the right `--path-prefix`, or trust the CN on B. |
| `404 NotFound` on every call | Unknown path prefix. | The connection's `--path-prefix` must equal a namespace prefix. |
| `404 KeyNotFound` | The `--external-key-id` is not a key in this namespace (case-sensitive; destroyed keys too). | Create the key in the namespace; the id is immutable per key version in Managed HSM. |
| `400 UnsupportedApiVersion`, `400 InvalidKeyName`, `400 UnsupportedAlgorithm`, `400 InvalidCiphertext` | Contract violations (see the spec section 4.4). | The Request tab shows exactly what arrived. |
| `403 KeyDisabled` / `KeyExpired` | The key is disabled or expired in EkmMock. | Enable it or clear the expiry. |
| `429 TooManyRequests` | The concurrency limit or the 200 ms internal deadline, or a fault. | Section 9, section 10. |
| `503 HsmUnavailable` | Engine unavailable: key store not loaded, "HSM offline" fault, or a corrupt key. | About page (self-test, master-key status). |
| SAN mismatch (seen on the **Azure** side, no EkmMock event at all) | Managed HSM refused the server certificate: its SAN is not the `--host`. | Re-issue the certificate with the right SAN (section 4). No handshake reaches EkmMock, so look at `az keyvault ekm-connection check` and the `EkmProxyAvailability` `FailureReason`. |

**Connection reuse.** The Connections page shows requests per connection, ALPN (`h2` or `http/1.1`) and handshake time: a new TLS handshake per call eats the latency budget (Managed HSM is expected to reuse connections; keep-alive is 120 s here).

## 7. Azure-side logs: diagnostic settings and KQL

**What to turn on** (Learn, "Logging and monitoring for Managed HSM external key management"): on the Managed HSM resource, **Diagnostic settings, Add**, under **Logs** select **AuditEvent**, and send to a **Log Analytics workspace** (to query and alert with KQL; add a storage account for retention). EKM calls appear in the same stream as other Managed HSM operations, identified by `OperationName`.
There is also the platform metric **`EkmProxyAvailability`** (namespace `Microsoft.KeyVault/managedHSMs`, aggregation Average, 100 on a successful `info` probe, 0 on a failure; dimensions `FailureReason`, `ResultType`, `StatusCode`, `Target`). Alert on it unsplit; split only the chart to diagnose.
`FailureReason` values: `ProxyConnectionError`, `ProxyTimeoutError`, `ProxyServerError`, `InternalServerError`.

**The four Azure-side operation names:** `EkmGetProxyInfo` (the probe and `ekm-connection check`), `EkmGetKeyMetadata`, `EkmWrapKey`, `EkmUnwrapKey`. (The spec and the Learn quickstart text speak of `EkmProxyOperation` records; the logging article only ever uses `AzureDiagnostics` with these `OperationName` values:
[OQ 70](OPEN-QUESTIONS.md).)

KQL from the Learn quickstart ("View audit logs") and the logging article, unchanged:

```kusto
// Recent EKM activity, including probes and manual checks
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where OperationName contains "Ekm"
| project TimeGenerated, Resource, OperationName, requestUri_s, ResultType, ResultDescription
| order by TimeGenerated desc
```

```kusto
// Failures of customer-initiated operations in the last 24 hours (excludes probes and manual checks)
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where OperationName in ("EkmWrapKey", "EkmUnwrapKey", "EkmGetKeyMetadata")
| where ResultType != "Success"
| where TimeGenerated > ago(24h)
| summarize Failures = count() by ResultType, ResultDescription, bin(TimeGenerated, 1h)
| order by TimeGenerated desc
```

```kusto
// Latency distribution of customer-initiated operations (Learn: if DurationMs is not populated, correlate with proxy logs instead;
// proxy logs capture end-to-end latency including the HSM call that DurationMs does not include)
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where OperationName in ("EkmWrapKey", "EkmUnwrapKey", "EkmGetKeyMetadata")
| where TimeGenerated > ago(1h)
| summarize p50 = percentile(DurationMs, 50), p95 = percentile(DurationMs, 95), p99 = percentile(DurationMs, 99) by bin(TimeGenerated, 5m)
```

`ResultDescription` carries the HTTP status the proxy returned; an empty `ResultDescription` means the request never reached the proxy (connection or TLS failure).

## 8. Correlating the console's `correlation_id` with Azure-side entries

Managed HSM puts `request_context` (`request_id`, `correlation_id`, `pool_name`) into every request body; EkmMock records all three for every exchange (including rejected ones). Learn says to correlate by those fields, by the **external key identifier inside `requestUri_s`**, and by a **timestamp within +/- 1 second** (allow for clock skew).

1. In Live traffic open the exchange; on **Exchange detail** copy the ready-made KQL (button "Copy KQL"), or `GET /api/console/exchanges/<id>/kql`. It is generated by the repository's `KqlSnippets`.
2. Run it in the Log Analytics workspace. Example output for `correlation_id` `aa9a3cb4-82b4-11f0-afc6-5ffd3bdade85` on an `unwrapkey` exchange:

   ```kusto
   // Managed HSM audit records for this EKM call (correlation_id from the request context)
   AzureDiagnostics
   | where ResourceProvider == "MICROSOFT.KEYVAULT"
   | where OperationName == "EkmUnwrapKey"
   | where column_ifexists("correlationId_g", "") == "aa9a3cb4-82b4-11f0-afc6-5ffd3bdade85" or column_ifexists("CorrelationId", "") == "aa9a3cb4-82b4-11f0-afc6-5ffd3bdade85"
   | project TimeGenerated, Resource, OperationName, requestUri_s, ResultType, ResultDescription
   | order by TimeGenerated asc
   ```

   and the documented fallback (key identifier within one second of the exchange):

   ```kusto
   let exchangeTime = datetime(2026-11-09T14:03:21.1234567Z);
   AzureDiagnostics
   | where ResourceProvider == "MICROSOFT.KEYVAULT"
   | where OperationName == "EkmUnwrapKey"
   | where TimeGenerated between ((exchangeTime - 1s) .. (exchangeTime + 1s))
   | where requestUri_s has "aes-key-1"
   | project TimeGenerated, Resource, OperationName, requestUri_s, ResultType, ResultDescription
   | order by TimeGenerated asc
   ```

3. **Honest caveat ([OQ 26](OPEN-QUESTIONS.md)):** Learn lists the correlation column as `correlationId_g` in one article and `CorrelationId` in another and never states that it *equals* the proxy request context's `correlation_id`. That is why the snippet tries both columns (`column_ifexists`) and offers the key-and-time fallback. Confirm with real rows next to a captured exchange and record the answer in RESULTS.
4. A request that appears in Managed HSM's log but **not** in Live traffic never reached EkmMock: look for a handshake failure on the Connections page, or for an NSG/DNS problem (Learn's triage workflow, step 3).

## 9. Latency-budget triage (150 and 250 ms)

Managed HSM enforces a hard **250 ms** per-request budget end to end (it times out and returns an error to the Azure service). EkmMock marks 150 ms (amber, a Warning log line) and 250 ms (red, an Error log line); the internal deadline is 200 ms, after which a request that has not started its crypto call gets an immediate 429.

1. **Find where the time goes.** Exchange detail, Timing tab: queue, auth, injected delay, crypto, total. On this machine's measurements the server side is about 0.4 ms (AES) to 8 ms (RSA-4096) at p50, so a slow exchange is almost always **injected delay, queueing at the concurrency limit, or a stall**, not crypto. An injected delay is badged on the row.
2. **Compare the two sides.** Server time in EkmMock versus `DurationMs` on the Azure side (section 7). The difference is roughly network plus Managed HSM overhead. The pool and the proxy must be in the **same region**.
3. **Many new connections?** A TLS handshake per call adds round trips: look at requests per connection on the Connections page.
4. **Load.** `ekmmock_inflight_requests` close to `Limits:MaxConcurrency` (64) means 429s soon. Check the dashboard's share over 250 ms.
5. **Stalls.** The local benchmark saw rare 100 to 340 ms stalls at 30k req/s on a shared machine ([benchmarks](benchmarks/README.md), [OQ 55](OPEN-QUESTIONS.md)); a 2-vCPU VM has not been measured ([OQ 64](OPEN-QUESTIONS.md)). If you see periodic stalls, run `ekmmock test bench` from another machine against the VM.
6. Note: `ekmmock_budget_exceeded_total` counts requests past the **internal deadline**, not the 250 ms colour ([OQ 50](OPEN-QUESTIONS.md)); use the console's over-budget filter and the Azure-side p95.

## 10. Fault-injection playbook

Faults exist only when the server was started with `EKMMOCK_ENABLE_FAULTS=true` (the VM template sets it only with the parameter `enableFaultInjection = true`, default **false**, like the ACI template; the compose file does not). Rules are global or scoped to a namespace, key and operation; they appear as badges in Live traffic and a banner on every page. **Always clear them afterwards.**

| Scenario | How | What you should see | Azure-side question (open: see RESULTS) |
|---|---|---|---|
| Distant HSM | `ekmmock faults preset --id distant-hsm-100` (also `-200`, `-260`); any other delay: console Fault injection page, or `POST /api/console/faults {"kind":"delay","delay_ms":240}` | Rows go amber/red; `injected_delay_ms` in the log; calls above 250 ms fail on the Azure side | At what delay does Managed HSM start failing; what does the error look like |
| Flaky proxy | `preset --id error-503-50`, or an error rule with status 429/500/503 and a percentage | A fraction of 5xx/429 | Retry behaviour of Managed HSM and of the workload |
| HSM offline | `preset --id hsm-offline` | `info` and every operation answer `503 HsmUnavailable`; the dashboard heartbeat keeps arriving (it is the 503 being served) | Effect on `az keyvault ekm-connection check`, on `EkmProxyAvailability`, and on a CMK workload |
| Blackhole | console rule kind `blackhole` (held until the client gives up, capped by `Faults:BlackholeMaxHoldSeconds`, 600 s) | The exchange stays open, then `ClientAborted` | How long Managed HSM waits; what the workload reports |
| Close connection | console rule kind `close` | Status 499 "no response", `ClosedByServer` | Handshake/connection error handling |
| Key disabled (temporary) | rule kind `key_disabled`, or disable the key on the Keys page | `403 KeyDisabled` on wrap/unwrap, `metadata` still 200 | How the CMK workload reacts and how soon |

Faults answer **before** authentication for offline, error and close (an anonymous caller sees 503/429/500 or a reset instead of 401); blackhole, delay and key-disabled apply only to authenticated callers ([OQ 51](OPEN-QUESTIONS.md)). Auto-expiry (up to one week) prevents a forgotten rule; `ekmmock faults clear` removes everything.
[`e2e.sh`](../deploy/azure/e2e.sh) automates the sweep (50, 100, 150, 200, 240, 260, 300 ms) and the offline/blackhole scenarios.

## 11. Metrics and Prometheus

The console port serves `/metrics` (Prometheus text, hand-written exporter, no dependency): `ekmmock_requests_total{op,status,namespace}`, `ekmmock_request_duration_seconds{op}` (buckets 5 ms to 1 s with 150 and 250 ms), `ekmmock_crypto_duration_seconds{op,alg}`, `ekmmock_budget_exceeded_total{op}`,
`ekmmock_tls_handshake_failures_total{reason}`, `ekmmock_inspector_dropped_total`, `ekmmock_inflight_requests`. It follows the console authentication (loopback only in `LoopbackOnly`; set `Metrics:AllowAnonymous=true` only if you understand the exposure).

On the VM the console is loopback only, so scrape **from the VM** (a Prometheus or agent on the same host, or through the SSH tunnel). With the generated certificate (SANs `localhost` and `127.0.0.1`):

```yaml
scrape_configs:
  - job_name: ekmmock
    scheme: https
    metrics_path: /metrics
    tls_config:
      ca_file: /opt/ekmmock/data/tls/root-ca.pem   # the public root CA
      server_name: localhost
    static_configs:
      - targets: ['127.0.0.1:8080']
```

Log lines (one per request, no bodies, no `value`/`n`/`e`) can be dropped under extreme overload ([OQ 54](OPEN-QUESTIONS.md)); metrics and the inspector are independent of that.

## 12. VM, container and ACI operations

- **SSH** only from the address in the NSG (`allowedSshSourceAddress`); the console tunnel is `ssh -N -L 8080:127.0.0.1:8080 <user>@<fqdn>`, then `https://127.0.0.1:8080`. To change the allowed address: update the NSG rule `allow-ssh-from-operator`.
- **Open the console to run the CLI:** keep the tunnel up and use `--console https://127.0.0.1:8080 --console-ca root-ca.pem` (the generated certificate includes `127.0.0.1` and `localhost` as SANs).
- **Disk full / logs:** Docker's default json-file logs are unbounded: for a long-running VM add `--log-opt max-size=50m --log-opt max-file=3` to the `docker run` in `ekmmock-vm.sh` (not set by default).
- **Cost:** a running B2s, disk and Standard public IP are billed. Auto-shutdown takes the endpoint offline (Managed HSM sees a failing proxy); if you accept that: `az vm auto-shutdown -g <rg> -n <vm> --time 1900`.
- **ACI:** `az container logs -g <rg> -n <group>`, `az container restart ...`, `az container exec ... --exec-command "ekmmock health"`. The console is on the second public port with Entra sign-in. ACI has no read-only root file system and its 443-as-non-root behaviour is unverified ([OQ 6](OPEN-QUESTIONS.md)).
- **Changing the image/config on ACI** means redeploying the template; the Azure Files share keeps `/data`.

## 13. Troubleshooting matrix

Adapted from Learn's triage table ("Troubleshoot Managed HSM external key management") and mapped to what EkmMock shows.

| Symptom | Likely layer | First look in EkmMock | Typical fix |
|---|---|---|---|
| `az keyvault ekm-connection check` fails with an mTLS/handshake error | Managed HSM to proxy: server certificate | Nothing arrives at all, or Connections shows `client_cert_not_trusted` | Server cert must chain to the **root** passed to `--server-ca-certificate` (not the leaf); SAN = `--host`; not expired. Update the connection first when the root changes (section 4). |
| `check` times out / DNS failure | Network | Nothing arrives | The DNS label resolves to the VM IP; NSG allows 443 from Internet; the container listens (`docker ps`, health); EKM listens on TCP **443** (other ports are not supported). |
| `check` returns 401/403 | Proxy authentication | 401 rows with the CN/chain facts | Import the current `certificate show` output (section 5). |
| 401/403 on all operations after it worked | Client certificate rotation | Same as above | Section 5. |
| `404 KeyNotFound` | Key registration | The `key` and `namespace` on the row | External key id mismatch (case, prefix, namespace), key destroyed. |
| `400` | Algorithm or payload | The Request and Response tabs, the ProxyError `code` | Unsupported `alg` for the key type, wrong size, base64url problems. |
| 408/502/503 | Proxy to HSM | `503 HsmUnavailable`: About page | Engine unavailable or fault active. (EkmMock has no real HSM behind it, so 502/408 only appear if injected.) |
| `429` | Concurrency or deadline | `ekmmock_inflight_requests`, injected faults | Section 9. |
| Intermittent failures | Capacity or network | Dashboard errors by code, share over 250 ms | Section 9; bench from another machine. |
| Workload (for example Storage CMK) reports a key error | Anywhere | Is the call in Live traffic? | Correlate (section 8); check key state (disabled/expired/destroyed) and the heartbeat. |
| Everything is `Corrupt` / 503 after a restart | Master key | About page: master-key status, self-test | Wrong or missing master key: restore the correct one (section 3). **Do not** start with `--dev`. |
| Console unreachable | Tunnel | | Tunnel up? `ssh -N -L 8080:127.0.0.1:8080`; the container is healthy; console URL `https://127.0.0.1:8080`. |

## 14. Clean-up order and destructive actions

**Destroying a key in EkmMock (crypto-shred) or losing the master key makes data protected by it unrecoverable. EkmMock keys cannot be exported and there is no undo.** Managed HSM does not support backup/restore of external keys (Learn).

Order (spec section 15; [`e2e.sh cleanup`](../deploy/azure/e2e.sh) does steps 2 to 4 after `--yes`):

1. **Move every workload off the key** (Learn: "migrate the workload to another key" before deleting the reference or connection) and keep the external key and its connection as long as the workload's data, backups or snapshots need them.
2. `az keyvault key delete --hsm-name <hsm> --name <key-ref>` (the Managed HSM key reference; the key material in EkmMock is unaffected). Deleted keys stay soft-deleted for the retention period.
3. `az keyvault ekm-connection delete --hsm-name <hsm>`.
4. Destroy the keys in EkmMock (console Keys page, type the key name; or `ekmmock key destroy --ns <ns> --name <key> --confirm <key>`).
5. Delete the VM: `az group delete --name <resource-group> --yes --no-wait` (this also deletes the OS disk with the key store, the CA key and the master-key copy on it: be sure you have what you need).
