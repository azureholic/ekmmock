// EkmMock on Azure Container Instances (spec 11.3: the ALTERNATIVE to the VM template; vm.bicep is the recommended one).
//
// SIMULATOR, NOT AN HSM: EkmMock is a software HSM for testing Azure Key Vault Managed HSM external key management (EKM). Never protect real data with it.
//
// What this deploys: one container group (public IP with a DNS name label, TCP pass-through, no front end), a storage account with an Azure Files share for /data.
//   - EKM endpoint: public TCP 443. ACI exposes the container port directly (NO port remapping), so the app listens on 443 INSIDE the container (Endpoints__Ekm__Url=https://0.0.0.0:443).
//     TLS 1.3 and mutual TLS terminate in the app, so it sees the Managed HSM client certificate.
//   - Console: a SECOND public port (consolePort, default 8443) with Entra ID sign-in (Console:Auth=EntraId). The loopback-only console of the VM model cannot be used here: ACI has no way to
//     tunnel to a loopback port. Everyone on the internet can reach that port; only the Entra users/group you allow get past the sign-in. Register the redirect URI
//     https://<fqdn>:<consolePort>/signin-oidc on the app registration.
//   - Secrets: the master key, the Entra client secret and the server certificate's private key are `secureValue` environment variables / a secret volume: ACI never returns them.
//     They are never template outputs.
//
// KNOWN LIMITATIONS OF ACI, stated honestly (details: deploy/azure/README.md, docs/OPEN-QUESTIONS.md question 6 and the "ACI" items):
//   1. Port 443 as a non-root user is UNVERIFIED in ACI. On Docker the non-root user binds 443 because the engine sets net.ipv4.ip_unprivileged_port_start=0; in ACI that sysctl cannot be
//      set or inspected. If the container exits with "Permission denied" on 443, the fallbacks are: the VM model (recommended), or `runAsRoot = true` (below, loudly a deviation from spec 5.5).
//   2. ACI cannot set sysctls or add capabilities, and it offers NO read-only root file system: the spec 5.5 hardening (`--read-only`, `--cap-drop ALL`, `no-new-privileges`) is NOT available
//      here. The container's writable layer is on the ACI host; /data is the Azure Files share.
//   3. Azure Files is mounted over SMB with the storage account key (no managed identity for the mount). The key is read inside the template with listKeys() and is never output.
//      File ownership and mode semantics on the SMB mount are ACI's, not Linux's: whether the non-root user can create and chmod its files there is UNVERIFIED.
//   4. The public IP of a container group cannot be placed behind an NSG; nothing at the ACI level restricts who can connect. Mutual TLS (client certificate CN + root CA allow-list in the
//      app) is the access control for the EKM port, Entra ID for the console port.
//   5. A secret volume is read-only, so uploading a new certificate in the console cannot persist it; renew the certificate by redeploying with new serverCertificatePem/serverCertificateKeyPem.
//   6. ANYONE WHO HOLDS THE STORAGE ACCOUNT KEY (the account needs shared-key access for the SMB mount, and the key can be read by anyone with the Contributor/Storage Account Key Operator
//      role on the account) can read the /data share. That share holds the ASP.NET Data Protection key ring of the console, which is NOT encrypted at rest (open question 63), so such a
//      person can forge a console session cookie (and read the key store file, whose key blobs stay encrypted under the master key). The storage account is hardened as far as the ACI mount allows
//      (TLS 1.2 minimum, HTTPS only, no public blob access) but it has NO network deny rule: ACI cannot be named in a storage firewall without a VNet, and a deny rule would break the mount.
//      Treat the storage account key like the console's admin password: restrict who has the Contributor/Storage Account Key Operator role, rotate the key (az storage account keys renew,
//      then redeploy) when someone leaves, and prefer the VM model, or a later VNet-integrated variant with a storage service endpoint, when this matters.
//
// DO NOT put a TLS-terminating front end (Application Gateway, Front Door, Container Apps HTTP ingress) in front of the EKM endpoint: the app must see the Managed HSM client certificate
// itself. This template deliberately contains none. No Private Link IaC either (spec 11.4: later). Container Apps, AKS and App Service are not supported targets.
//
// Region: deploy in the SAME REGION as the Managed HSM pool (the 250 ms budget includes the network distance).

targetScope = 'resourceGroup'

// ---------------------------------------------------------------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------------------------------------------------------------

@description('Azure region. Use the SAME region as the Managed HSM pool: the 250 ms budget of every wrap/unwrap includes the network distance between the pool and the container.')
param location string = resourceGroup().location

@description('Prefix for resource names (lowercase letters and digits, starting with a letter). A unique suffix derived from the resource group is appended.')
@minLength(3)
@maxLength(8)
param namePrefix string = 'ekmmock'

@description('DNS name label of the container group: the proxy host name is <label>.<location>.azurecontainer.io. The FQDN must be the SAN of serverCertificatePem and the --host of the EKM connection. Lowercase letters, digits and hyphens; unique per region.')
@minLength(3)
@maxLength(63)
param dnsNameLabel string = '${namePrefix}-${uniqueString(resourceGroup().id)}'

@description('The EkmMock image ACI pulls, for example "myregistry.azurecr.io/ekmmock:0.2.0" (use a version tag or digest, not "latest"). ACI must be able to pull it: a public registry, or your registry with imageRegistryCredentials. ghcr.io/azureholic/ekmmock is NOT published: build and push deploy/docker/Dockerfile yourself.')
@minLength(1)
@maxLength(255)
param containerImage string

@description('Credentials for a private registry as an object: { "server": "myregistry.azurecr.io", "username": "...", "password": "..." } (SECRET; use a pull-only token). Leave empty for a public image.')
@secure()
param imageRegistryCredentials object = {}

@description('CPU cores of the container (the EKM endpoint is light; AES operations take well under a millisecond).')
@minValue(1)
@maxValue(4)
param cpuCores int = 1

@description('Memory of the container in GiB (the server uses about 130 MiB idle).')
@minValue(1)
@maxValue(16)
param memoryInGb int = 2

@description('Run the container as root (uid 0). DEFAULT FALSE, and it should stay false. This is a loud deviation from spec 5.5 (non-root), meant ONLY as the last resort if the non-root user cannot bind port 443 in ACI (open question 6). Whether ACI honours runAsUser outside confidential containers is itself unverified; if the deployment is rejected, use the VM model.')
param runAsRoot bool = false

@description('The public TCP port of the console (Entra ID sign-in). It must not be 443 (the EKM endpoint).')
@minValue(1024)
@maxValue(65535)
param consolePort int = 8443

@description('The Key Store Master Key: 32 random bytes, base64 (44 characters), for example from `openssl rand -base64 32`. SECRET. Delivered as a secureValue environment variable (EKMMOCK_MASTER_KEY); never an output. It encrypts every key in the key store; losing it makes every key unrecoverable.')
@secure()
@minLength(44)
@maxLength(44)
param masterKey string

@description('The server certificate chain (PEM text, leaf first) for the FQDN <dnsNameLabel>.<location>.azurecontainer.io. Public information. Generate a test one with `ekmmock certs ca` and `ekmmock certs server --fqdn <fqdn>` (see deploy/azure/README.md).')
@minLength(100)
param serverCertificatePem string

@description('The private key (PKCS#8 PEM) of the server certificate. SECRET. Delivered in a read-only secret volume; never an output.')
@secure()
@minLength(100)
param serverCertificateKeyPem string

@description('Entra tenant ID (a GUID) of the app registration used for the console sign-in.')
@minLength(36)
@maxLength(36)
param entraTenantId string

@description('Application (client) ID (a GUID) of the app registration used for the console sign-in. Its redirect URI is https://<fqdn>:<consolePort>/signin-oidc.')
@minLength(36)
@maxLength(36)
param entraClientId string

@description('Object IDs (GUIDs) of the Entra users allowed to use the console. Provide this and/or entraAllowedGroupId; the console refuses to start in EntraId mode without an allow-list.')
param entraAllowedObjectIds array = []

@description('Object ID (a GUID) of an Entra security group whose members may use the console (needs the groups claim). Empty to rely on entraAllowedObjectIds only.')
param entraAllowedGroupId string = ''

@description('The client secret of the Entra app registration. SECRET. Delivered as a secureValue environment variable (EKMMOCK_CONSOLE_CLIENT_SECRET); never an output.')
@secure()
@minLength(8)
param entraClientSecret string

@description('Start with EKMMOCK_ENABLE_FAULTS=true so that the console and CLI can inject delays, errors, HSM-offline and blackhole faults (needed for the spec 15 scenarios). Off by default here because the console port is reachable from the internet (behind Entra ID).')
param enableFaultInjection bool = false

@description('Quota of the Azure Files share that holds /data (key store, namespaces, audit log), in GiB.')
@minValue(1)
@maxValue(100)
param fileShareQuotaGiB int = 5

@description('Extra tags for every resource.')
param tags object = {}

// ---------------------------------------------------------------------------------------------------------------------------------
// Variables
// ---------------------------------------------------------------------------------------------------------------------------------

var suffix = uniqueString(resourceGroup().id)
var storageAccountName = take('${namePrefix}${suffix}', 24)
var shareName = 'ekmmock-data'
var resourceTags = union(
  {
    application: 'ekmmock'
    purpose: 'test-only-simulator-not-an-hsm'
  },
  tags
)

// The EKM endpoint listens on 443 inside the container because ACI cannot remap ports.
var ekmPort = 443

var entraAllowedObjectIdVariables = [
  for (objectId, index) in entraAllowedObjectIds: {
    name: 'Console__EntraId__AllowedObjectIds__${index}'
    value: objectId
  }
]

var environmentVariables = concat(
  [
    { name: 'Endpoints__Ekm__Url', value: 'https://0.0.0.0:${ekmPort}' }
    { name: 'Endpoints__Console__Url', value: 'https://0.0.0.0:${consolePort}' }
    // The bundled CLI (ekmmock ... via `az container exec`) finds the console here.
    { name: 'EKMMOCK_CONSOLE', value: 'https://127.0.0.1:${consolePort}' }
    { name: 'Console__Auth', value: 'EntraId' }
    { name: 'Console__EntraId__TenantId', value: entraTenantId }
    { name: 'Console__EntraId__ClientId', value: entraClientId }
    { name: 'Tls__CertFile', value: '/run/ekmmock-tls/server.crt' }
    { name: 'Tls__KeyFile', value: '/run/ekmmock-tls/server.key' }
    { name: 'EKMMOCK_ENABLE_FAULTS', value: enableFaultInjection ? 'true' : 'false' }
    { name: 'EKMMOCK_ALLOW_KEY_IMPORT', value: 'false' }
    // Inspector memory bounds for the small container (2 GiB by default): the ring buffer holds at most 2000 exchanges AND about 32 MiB (estimated); the capture queue 1024 records.
    // Anonymous internet traffic reaches the inspector, so it is bounded in bytes, not only in count (docs/DECISIONS.md "Security review follow-up").
    { name: 'Inspector__RingBufferSize', value: '2000' }
    { name: 'Inspector__MaxBytes', value: '33554432' }
    { name: 'Inspector__ChannelCapacity', value: '1024' }
    // Secrets: secureValue is never returned by the ACI API and never shown in the portal.
    { name: 'EKMMOCK_MASTER_KEY', secureValue: masterKey }
    { name: 'EKMMOCK_CONSOLE_CLIENT_SECRET', secureValue: entraClientSecret }
  ],
  entraAllowedObjectIdVariables,
  entraGroupVariables
)

// ACI refuses an environment variable without a value, so the group id is only set when there is one.
var entraGroupVariables = empty(entraAllowedGroupId)
  ? []
  : [
      { name: 'Console__EntraId__AllowedGroupId', value: entraAllowedGroupId }
    ]

var registryCredentials = empty(imageRegistryCredentials)
  ? []
  : [
      {
        server: imageRegistryCredentials.server
        username: imageRegistryCredentials.username
        password: imageRegistryCredentials.password
      }
    ]

// ---------------------------------------------------------------------------------------------------------------------------------
// Storage for /data (Azure Files)
// ---------------------------------------------------------------------------------------------------------------------------------

resource storageAccount 'Microsoft.Storage/storageAccounts@2025-01-01' = {
  name: storageAccountName
  location: location
  tags: resourceTags
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    allowBlobPublicAccess: false
    // The ACI Azure Files mount authenticates with the account key: shared key access must stay on for this account.
    allowSharedKeyAccess: true
    publicNetworkAccess: 'Enabled'
  }
}

resource fileService 'Microsoft.Storage/storageAccounts/fileServices@2025-01-01' = {
  parent: storageAccount
  name: 'default'
}

resource fileShare 'Microsoft.Storage/storageAccounts/fileServices/shares@2025-01-01' = {
  parent: fileService
  name: shareName
  properties: {
    shareQuota: fileShareQuotaGiB
    enabledProtocols: 'SMB'
  }
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Container group
// ---------------------------------------------------------------------------------------------------------------------------------

resource containerGroup 'Microsoft.ContainerInstance/containerGroups@2025-09-01' = {
  name: '${namePrefix}-aci-${suffix}'
  location: location
  tags: resourceTags
  properties: {
    osType: 'Linux'
    restartPolicy: 'Always'
    imageRegistryCredentials: registryCredentials
    ipAddress: {
      type: 'Public'
      // The legacy (Unsecure) label scope is kept on purpose: the FQDN must be <label>.<location>.azurecontainer.io, known BEFORE the deployment, because it is the SAN of the server certificate.
      // The secure scopes (autoGeneratedDomainNameLabelScope) add a hash to the name that cannot be known in advance. Trade-off: a deleted label could be taken over by someone else.
      dnsNameLabel: dnsNameLabel
      ports: [
        {
          protocol: 'TCP'
          port: ekmPort
        }
        {
          protocol: 'TCP'
          port: consolePort
        }
      ]
    }
    containers: [
      {
        name: 'ekmmock'
        properties: {
          image: containerImage
          ports: [
            {
              protocol: 'TCP'
              port: ekmPort
            }
            {
              protocol: 'TCP'
              port: consolePort
            }
          ]
          resources: {
            requests: {
              cpu: cpuCores
              memoryInGB: memoryInGb
            }
          }
          environmentVariables: environmentVariables
          // Only when runAsRoot is true (see the parameter): otherwise the image's own non-root user (uid 1654) runs the process.
          securityContext: runAsRoot
            ? {
                runAsUser: 0
                runAsGroup: 0
              }
            : null
          volumeMounts: [
            {
              name: 'data'
              mountPath: '/data'
              readOnly: false
            }
            {
              name: 'tls'
              mountPath: '/run/ekmmock-tls'
              readOnly: true
            }
          ]
        }
      }
    ]
    volumes: [
      {
        name: 'data'
        azureFile: {
          shareName: fileShare.name
          storageAccountName: storageAccount.name
          // The SMB mount needs the account key. It stays inside this template (never an output).
          storageAccountKey: storageAccount.listKeys().keys[0].value
          readOnly: false
        }
      }
      {
        name: 'tls'
        secret: {
          'server.crt': base64(serverCertificatePem)
          'server.key': base64(serverCertificateKeyPem)
        }
      }
    ]
  }
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Outputs (never a secret)
// ---------------------------------------------------------------------------------------------------------------------------------

@description('The public FQDN of the EKM endpoint: use it as --host of "az keyvault ekm-connection create". It must be the SAN of the server certificate.')
output fqdn string = containerGroup.properties.ipAddress.fqdn

@description('The public IP address of the container group.')
output ipAddress string = containerGroup.properties.ipAddress.ip

@description('The EKM endpoint (port 443, mutual TLS: it answers 401 without a client certificate).')
output ekmUrl string = 'https://${containerGroup.properties.ipAddress.fqdn}'

@description('The console (Entra ID sign-in). Register https://<fqdn>:<consolePort>/signin-oidc as a redirect URI on the app registration.')
output consoleUrl string = 'https://${containerGroup.properties.ipAddress.fqdn}:${consolePort}'

@description('The name of the container group.')
output containerGroupName string = containerGroup.name

@description('The storage account that holds the /data share.')
output storageAccountName string = storageAccount.name

@description('The Azure Files share mounted at /data.')
output fileShareName string = fileShare.name
