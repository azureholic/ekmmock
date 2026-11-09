# Deploying EkmMock to Azure (test environment)

> **EkmMock is a simulator, not an HSM. Never protect real data with it.** These templates create a *test* proxy for Azure Key Vault Managed HSM external key management (EKM).
>
> **Status: nothing here has been deployed.** Both templates were built, linted and formatted offline (Bicep 0.42); the e2e script was run only with `--dry-run`, `bash -n`, shellcheck and a local test double of `az`.
> The VM boot flow, ACI, and every interaction with a real Managed HSM are **unverified** (see [Unverified](#what-is-unverified)). Nothing was deployed and no Azure resource was created while writing them.

| File | What it is |
|---|---|
| [`vm.bicep`](vm.bicep) | **Recommended.** Ubuntu 24.04 VM with Docker: Standard static public IP + DNS label, NSG, VNet, cloud-init. |
| [`cloud-init.yaml`](cloud-init.yaml), [`vm-setup.sh`](vm-setup.sh) | First-boot configuration (installed by `vm.bicep`); `vm-setup.sh` is also the on-VM tool (`bootstrap`, `run`, `upgrade`, `status`). |
| [`aci.bicep`](aci.bicep) | **Alternative, more unverified.** Azure Container Instances with a public IP + DNS label and an Azure Files share. |
| [`vm.example.bicepparam`](vm.example.bicepparam), [`aci.example.bicepparam`](aci.example.bicepparam) | Example parameter files with `<REPLACE-...>` placeholders. Copy to `*.local.bicepparam` (git-ignored). |
| [`e2e.sh`](e2e.sh) | The end-to-end test against a real Managed HSM (spec section 15). |
| [`bicepconfig.json`](bicepconfig.json) | Linter rules (secrets, recent API versions). |

**Not supported, on purpose:** a TLS-terminating front end of any kind (Application Gateway, Front Door, Container Apps HTTP ingress, a load balancer with TLS offload), App Service, AKS, Container Apps, and Private Link IaC. Managed HSM has to complete mutual TLS with the app itself; the app must see the client certificate (spec 11.3, 11.4).

## Prerequisites

- An existing **Managed HSM in a public Azure region** (EKM is not available in Azure Government or Azure China), in a subscription where the feature is registered:
  `az feature register --namespace Microsoft.KeyVault --name MHSM_EKM`, then wait for `az feature show --namespace Microsoft.KeyVault --name MHSM_EKM --query properties.state -o tsv` to say `Registered`.
- The data-plane roles **Managed HSM EKM Administrator** (manage the connection) and **Managed HSM Crypto User** (create and use keys) on the HSM.
- Azure CLI 2.x with Bicep (`az bicep install`; `az bicep version`). Tested with CLI 2.92.0 and Bicep 0.42.1. `az keyvault ekm-connection` exists in this CLI version (`create`, `check`, `show`, `update`, `delete`, `certificate show`); if yours lacks it, `az upgrade`.
- `openssl`, `ssh`/`scp`, and the `ekmmock` CLI (build `src/EkmMock.Cli`, or run it in the image).
- An **SSH key pair** (`ssh-keygen -t ed25519`) and your **public IP address**.
- Permission to create a resource group and the resources below (Contributor on the resource group). **You create the resource group; the templates do not.**

### Region

Deploy in **the same region as the Managed HSM pool**: every `wrapkey`/`unwrapkey` has a 250 ms budget end to end, so network distance is paid directly out of it.
Find the region: `az keyvault show --hsm-name <hsm> --query location -o tsv`. The VM's FQDN is `<label>.<location>.cloudapp.azure.com` (ACI: `<label>.<location>.azurecontainer.io`); the `--host` of the EKM connection must be that name and **TCP 443** must be reachable (other ports are not supported by Managed HSM).

### Cost

Running continuously: a `Standard_B2s` VM, a 64 GiB StandardSSD disk, a Standard static public IP (ACI: a 1 vCPU / 2 GiB container group, a storage account and a file share). Check the Azure pricing calculator for your region. **Delete the resource group when you are done** ([clean-up](#clean-up)).
Auto-shutdown would take the EKM endpoint offline, which Managed HSM sees as a failing proxy, so none is configured; if you want it anyway: `az vm auto-shutdown --resource-group <rg> --name <vm> --time 1900`.

## Secrets: never on the command line

The master key (and, for ACI, the Entra client secret and the server private key) are `@secure()` parameters. They are **never** template outputs, never written to a file in the repository, and must not appear in your shell history or process list.
The example parameter files read them with `readEnvironmentVariable(...)`, so the value only lives in an environment variable of the shell that runs `az`:

```bash
# bash: the master key is 32 random bytes, base64 (44 characters). Generate it, keep a copy, export it.
umask 077
openssl rand -base64 32 > "$HOME/ekmmock-master.key"        # BACK THIS UP (password manager / Key Vault): losing it makes every key unrecoverable
export EKMMOCK_MASTER_KEY="$(cat "$HOME/ekmmock-master.key")"
# a secret you type: read -rs keeps it out of the history
read -rs -p "Entra client secret: " EKMMOCK_ENTRA_CLIENT_SECRET; export EKMMOCK_ENTRA_CLIENT_SECRET
```

```powershell
# PowerShell 7
$bytes = New-Object byte[] 32; [Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
$env:EKMMOCK_MASTER_KEY = [Convert]::ToBase64String($bytes)
$env:EKMMOCK_MASTER_KEY | Set-Content -NoNewline "$HOME\ekmmock-master.key"     # back it up, then restrict the file's ACL
$env:EKMMOCK_ENTRA_CLIENT_SECRET = Read-Host -AsSecureString "Entra client secret" | ConvertFrom-SecureString -AsPlainText
```

A Key Vault reference works too in a `.bicepparam` file (`param masterKey = az.getSecret('<subscription-id>', '<resource-group>', '<key-vault>', '<secret-name>')`; the vault needs *Azure Resource Manager for template deployment* access enabled). Do **not** use `--parameters masterKey=<value>`: it ends up in your history and in the process list.
Anyone who can read the VM's OS disk, run commands on the VM, or read the deployment's custom data can read the master key: treat Azure RBAC on this resource group accordingly.

## Option 1 (recommended): the VM

```bash
az group create --name rg-ekmmock-test --location <region-of-the-hsm>      # you choose name and region
cp deploy/azure/vm.example.bicepparam deploy/azure/vm.local.bicepparam    # edit every <REPLACE-...> placeholder (git-ignored)
az deployment group create --resource-group rg-ekmmock-test --parameters deploy/azure/vm.local.bicepparam --query properties.outputs
```

The parameters that matter: `location` (the HSM's region), `sshPublicKey` (the **public** key line), `allowedSshSourceAddress` (your IP or CIDR; **required, no default, and `*`, `Internet`, `Any`, `0.0.0.0/0` are rejected**), `masterKey` (secure), the image source (below), `generateTestCertificate` (default `true`), `enableFaultInjection` (default `true`: needed for the spec 15 scenarios; rules can only be created from the loopback-only console). All parameters have descriptions: `bicep build deploy/azure/vm.bicep` or read the file.

What you get: an NSG that allows **443 from anywhere** (Managed HSM source IPs are not static and cannot be allow-listed; mutual TLS with client-certificate validation in the app is the access control) and **22 only from your address**; everything else, including the console port 8080, is denied.
SSH password login is disabled. The console stays on the VM's loopback.

### The image

No image is published (`ghcr.io/azureholic/ekmmock` does **not** exist), so there are two ways, chosen with `imageSource`:

- **`build` (default):** on first boot the VM clones `repoUrl` at `repoRef` (default `https://github.com/azureholic/ekmmock.git`, `main`) and runs `docker build -f deploy/docker/Dockerfile`. It takes a few minutes on a B2s. **Pin `repoRef` to a tag or a 40-character commit SHA** for a reproducible deployment: `main` moves.
- **`pull`:** set `imageSource = 'pull'` and `containerImage` to an image in **your own registry** (for example built with `az acr build --registry <acr> --image ekmmock:<version> --file deploy/docker/Dockerfile .`, which needs access to nuget.org). For a private registry also set `registryUsername` and the secure `registryPassword` (a pull-only token). Use a version tag or digest, not `latest`.

### First boot

cloud-init installs Docker from Docker's own apt repository (the signing key's fingerprint is verified against the published one and the install is refused if it differs), obtains the image, generates the certificates and starts the container with the same hardening as `deploy/docker/compose.yaml`
(`--read-only`, `--cap-drop ALL`, `no-new-privileges`, the image's non-root user, restart `unless-stopped`, the image's health check; the master key is mounted as a **read-only file**, mode 0400, owned by the container user). Watch it:

```bash
ssh <user>@<fqdn> sudo tail -f /var/log/ekmmock-bootstrap.log        # the exact command is the output bootstrapLogCommand
```

It ends with `EkmMock is ready`. Re-run steps later with `sudo /opt/ekmmock/bin/ekmmock-vm.sh status|run|upgrade`.

### The certificate flow (the SAN must equal the FQDN)

Managed HSM validates the proxy's server certificate against the **root CA** you register, and the certificate's **SAN must equal the `--host`** (the public FQDN, output `fqdn`). On first boot, with `generateTestCertificate = true`:

1. the VM's `ekmmock certs ca` creates a test **root CA** (10 years) and `ekmmock certs server --fqdn <fqdn> --san localhost --san 127.0.0.1` issues the **server certificate** (397 days) with SAN = the FQDN (plus `localhost` and `127.0.0.1` so that the console, reached through the tunnel, verifies against the same root);
2. the server certificate and key go to `/opt/ekmmock/data/tls/server.crt` and `server.key` (hot-reloaded when replaced); the **CA's private key stays in `/opt/ekmmock/data/pki/root-ca.key`** (mode 0600) so you can re-issue under the same root. **No private key ever leaves the VM**; delete `root-ca.key` if you do not want re-issue ability;
3. the **public** root certificate is `/opt/ekmmock/data/tls/root-ca.pem`. This is what `az keyvault ekm-connection create --server-ca-certificate` takes (the **root**, not the leaf). Get it with the output `fetchRootCaCommand`:

   ```bash
   scp <user>@<fqdn>:/opt/ekmmock/data/tls/root-ca.pem ./root-ca.pem      # or: console Certificates page, "Download root-ca.pem"
   openssl x509 -in root-ca.pem -noout -subject -dates -fingerprint -sha256   # check what you are about to register
   ```

**Bring your own certificate:** set `generateTestCertificate = false`, copy your PEM chain (leaf first) and key to `/opt/ekmmock/data/tls/server.crt` / `server.key` (owner uid 1654, key mode 0600), then `sudo /opt/ekmmock/bin/ekmmock-vm.sh run`. Register your CA's **root** certificate with Managed HSM.

### Reach the console

```bash
ssh -N -L 8080:127.0.0.1:8080 <user>@<fqdn>        # the output consoleTunnelCommand; leave it running
# browser or CLI:  https://127.0.0.1:8080     ekmmock ... --console https://127.0.0.1:8080 --console-ca root-ca.pem
```

### Then run the end-to-end test

```bash
export HSM=<managed-hsm-name> FQDN=<fqdn-output>
deploy/azure/e2e.sh --dry-run all        # read what it would do
deploy/azure/e2e.sh all                  # trust, connection, key references, wrap/unwrap round trip
```

See [`e2e.sh`](e2e.sh) (`--help`) and [`docs/RESULTS.md`](../../docs/RESULTS.md) for the scenarios and where to record them. **The script is unverified against a real Managed HSM.**

## Option 2 (alternative): Azure Container Instances

Read the header of [`aci.bicep`](aci.bicep) first. In short: ACI does TCP pass-through, so mTLS terminates in the app, but **ACI has no port remapping**, so the EKM endpoint listens on **443 inside the container**, and the console cannot be loopback-only: it gets a **second public port (default 8443) with Entra ID sign-in**.

**Known limitations (stated honestly):**

1. **Non-root binding of port 443 in ACI is unverified** ([OQ 6](../../docs/OPEN-QUESTIONS.md)). On Docker it works because the engine sets `net.ipv4.ip_unprivileged_port_start=0`; in ACI that cannot be set or inspected. If the container exits with `Permission denied`, use the VM, or the **last resort** parameter `runAsRoot = true` (default **false**; a loud deviation from spec 5.5; whether ACI honours `runAsUser` outside confidential containers is itself unverified), or build a derived image with `USER 0` and push it to your registry.
2. **No read-only root file system, no capability drop, no `no-new-privileges`** in ACI: the spec 5.5 hardening is not available there.
3. **Azure Files over SMB with the storage account key** (no managed identity for the mount): the key is read inside the template (`listKeys()`) and never output. File ownership and `chmod` semantics for uid 1654 on the SMB mount are unverified; the key store sets file modes.
4. **No NSG for a container group's public IP**: nothing restricts connections at the ACI level; mTLS (EKM) and Entra ID (console) are the only controls. The console is therefore exposed to the internet behind Entra sign-in.
5. The server certificate comes from a **read-only secret volume** (the console's certificate upload cannot persist it); renew by redeploying with new certificate parameters. The DNS label uses the legacy scope so that the FQDN is known in advance (needed for the certificate SAN); a deleted label could be taken over by someone else.

Steps:

```bash
# 1. Entra app registration for the console: redirect URI https://<fqdn>:8443/signin-oidc, a client secret, an exposed API scope (for the CLI: api://<client-id>/.default),
#    "allow public client flows" for the CLI's device code. Note tenant id, client id, your user's object id.
# 2. Choose the DNS label first: the FQDN is <label>.<region>.azurecontainer.io. Generate the TEST certificate for exactly that FQDN, locally:
ekmmock certs ca --out ./out/pki
ekmmock certs server --ca ./out/pki/root-ca.pem --ca-key ./out/pki/root-ca.key --fqdn <label>.<region>.azurecontainer.io --out ./out/pki
# 3. Make the image available to ACI (a registry ACI can pull from) and set containerImage (+ imageRegistryCredentials for a private registry).
# 4. Parameters and secrets (see the comments in the file; secrets from the environment):
cp deploy/azure/aci.example.bicepparam deploy/azure/aci.local.bicepparam
export EKMMOCK_MASTER_KEY=... EKMMOCK_ENTRA_CLIENT_SECRET=... EKMMOCK_SERVER_CERT_FILE=../../out/pki/server.crt EKMMOCK_SERVER_KEY_FILE=../../out/pki/server.key
az group create --name rg-ekmmock-aci --location <region-of-the-hsm>
az deployment group create --resource-group rg-ekmmock-aci --parameters deploy/azure/aci.local.bicepparam --query properties.outputs
```

The private key of the server certificate **does leave your machine** here (it is a secure parameter delivered to ACI as a secret volume); the CA key stays with you. Then `e2e.sh` with `--console https://<fqdn>:8443` and `EKMMOCK_CONSOLE_ARGS="--auth entra --tenant <id> --client-id <id>"` (or a token in `EKMMOCK_CONSOLE_TOKEN`).

## Validation done offline

```bash
bicep build deploy/azure/vm.bicep --stdout > /dev/null && bicep lint deploy/azure/vm.bicep      # 0 warnings (bicepconfig.json also checks recent API versions and secrets)
bicep build deploy/azure/aci.bicep --stdout > /dev/null && bicep lint deploy/azure/aci.bicep
bicep format deploy/azure/vm.bicep --outfile /tmp/f.bicep && diff deploy/azure/vm.bicep /tmp/f.bicep      # no diff
bash -n deploy/azure/e2e.sh deploy/azure/vm-setup.sh
docker run --rm -v "$PWD:/mnt" -w /mnt koalaman/shellcheck:stable -x -S style deploy/azure/e2e.sh deploy/azure/vm-setup.sh
deploy/azure/e2e.sh --dry-run --hsm contoso-hsm --fqdn ekm.example.test all
```

`az deployment group validate` and `what-if` need a subscription and an existing resource group (they call Azure), so they were **not run** here. When you have a resource group, run `az deployment group what-if --resource-group <rg> --parameters deploy/azure/vm.local.bicepparam` before the first deployment.
Do not commit `bicep build` output (`deploy/azure/*.json` is git-ignored except `bicepconfig.json`). CI builds and lints both templates (`az bicep build/lint`).

## What is unverified

- Both templates have **never been deployed**. API versions are the latest the Bicep 0.42 type library knows (network 2025-05-01, compute 2025-04-01, ACI 2025-09-01, storage 2025-01-01).
- The VM boot flow (cloud-init, the Docker install, image build on the VM, certificate generation, container start) was exercised in pieces only: the YAML renders and parses, the script passes `bash -n` and shellcheck and its helper functions ran in a shell; the Docker/OpenSSL parts were not run on a fresh Ubuntu VM.
- ACI: everything in the list above. A B2s VM in your region might also not be available (try another size).
- `e2e.sh` against a real Managed HSM; the exact shape of `az keyvault role ...` output used by the best-effort role check; the Azure-side behaviour in [`docs/RESULTS.md`](../../docs/RESULTS.md).

## Clean-up

**Order matters, and destroying a key or losing the master key makes protected data unrecoverable.** Move workloads off the key first; then `e2e.sh cleanup --yes` (or by hand: `az keyvault key delete`, `az keyvault ekm-connection delete`, destroy the keys in EkmMock), and only then delete the resource group:

```bash
az group delete --name rg-ekmmock-test --yes --no-wait        # VM, disk, IP, NSG, VNet (and the key store and CA key on that disk)
```

The OS disk, NIC and public IP are set to delete with the VM. Keep your master-key backup until you are sure that no data depends on the keys.
