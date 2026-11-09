// EkmMock on a small Linux VM with Docker (spec 11.3: the RECOMMENDED Azure test deployment).
//
// SIMULATOR, NOT AN HSM: EkmMock is a software HSM for testing Azure Key Vault Managed HSM external key management (EKM). Never protect real data with it.
//
// What this deploys: one Ubuntu 24.04 LTS VM (Docker, EkmMock container), a Standard static public IP with a DNS name label, a network security group, a VNet and a NIC.
//   - EKM endpoint: public TCP 443 -> container 8443. TLS 1.3 and mutual TLS terminate IN THE APP (Kestrel), so it sees the Managed HSM client certificate.
//   - Console: the container publishes it on the VM's loopback only (127.0.0.1:8080). It is reached with `ssh -L 8080:127.0.0.1:8080`. Port 8080 is NOT opened in the NSG, ever.
//   - NSG: inbound 443 from anywhere (Managed HSM source IPs are not static, so mTLS client-certificate validation is the only access control), inbound 22 ONLY from
//     `allowedSshSourceAddress`, everything else denied.
//   - The certificate: on first boot a test root CA and a server certificate whose SAN equals the public FQDN (output `fqdn`) are generated ON THE VM; the private keys never leave it.
//     The public root CA (root-ca.pem) is what `az keyvault ekm-connection create --server-ca-certificate` takes. See deploy/azure/README.md.
//
// DO NOT put a TLS-terminating front end (Application Gateway, Front Door, Container Apps HTTP ingress, a load balancer with TLS offload) in front of the EKM endpoint:
// the app must see the Managed HSM client certificate itself. This template deliberately contains none. No Private Link either (spec 11.4: later).
//
// Region: deploy in the SAME REGION as the Managed HSM pool. Every wrap/unwrap must finish within 250 ms end to end, so network distance eats the budget directly.
//
// Cost: a B2s VM, a 64 GiB StandardSSD disk and a Standard public IP run all the time. Delete the resource group when you are done. Auto-shutdown would take the EKM endpoint
// offline (the Managed HSM would see it as a failing proxy), so none is configured; see deploy/azure/README.md for the optional `az vm auto-shutdown` command.

targetScope = 'resourceGroup'

// ---------------------------------------------------------------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------------------------------------------------------------

@description('Azure region. Use the SAME region as the Managed HSM pool: the 250 ms budget of every wrap/unwrap includes the network distance between the pool and this VM.')
param location string = resourceGroup().location

@description('Prefix for resource names (lowercase letters and digits, starting with a letter). A unique suffix derived from the resource group is appended.')
@minLength(3)
@maxLength(12)
param namePrefix string = 'ekmmock'

@description('DNS name label of the public IP: the proxy host name is <label>.<location>.cloudapp.azure.com. The FQDN becomes the SAN of the server certificate and the --host of the EKM connection. Lowercase letters, digits and hyphens; unique per region.')
@minLength(3)
@maxLength(63)
param dnsLabel string = '${namePrefix}-${uniqueString(resourceGroup().id)}'

@description('VM size. Standard_B2s (2 vCPU, 4 GiB) is enough for a test; building the image on the VM takes a few minutes on it.')
param vmSize string = 'Standard_B2s'

@description('Administrator user name of the VM (SSH key login only; password authentication is disabled).')
@minLength(1)
@maxLength(32)
param adminUsername string = 'azureuser'

@description('The SSH PUBLIC key (one line, for example "ssh-ed25519 AAAA... you@laptop") that may log in as the administrator. This is not a secret; never put a private key here.')
@minLength(40)
param sshPublicKey string

@description('The only source address allowed to reach SSH (port 22): your public IP address or a CIDR range, for example "203.0.113.7" or "203.0.113.0/28". There is deliberately no default. "*", "Internet", "Any" and "0.0.0.0/0" are rejected.')
@minLength(7)
@maxLength(43)
param allowedSshSourceAddress string

@description('The Key Store Master Key: 32 random bytes, base64 (44 characters), for example from `openssl rand -base64 32`. SECRET. It encrypts every key in the EkmMock key store; losing it makes every key unrecoverable. Pass it from a file or an environment variable (see deploy/azure/README.md), never inline; it is never an output.')
@secure()
@minLength(44)
@maxLength(44)
param masterKey string

@description('Where the EkmMock image comes from: "build" clones repoUrl at repoRef on the VM and builds deploy/docker/Dockerfile (the default: no image is published anywhere), "pull" pulls containerImage from your own registry.')
@allowed([
  'build'
  'pull'
])
param imageSource string = 'build'

@description('With imageSource "build": the local tag given to the image built on the VM. With "pull": the full reference to pull (for example "myregistry.azurecr.io/ekmmock:0.2.0"; use a version tag or digest, not "latest"). ghcr.io/azureholic/ekmmock is NOT published.')
@minLength(1)
@maxLength(255)
param containerImage string = 'ekmmock:local'

@description('With imageSource "build": the git repository to build from (https only).')
@minLength(12)
@maxLength(255)
param repoUrl string = 'https://github.com/azureholic/ekmmock.git'

@description('With imageSource "build": the branch, tag or full commit SHA to build. For a reproducible deployment use a tag or a 40-character commit SHA instead of the moving branch "main".')
@minLength(1)
@maxLength(255)
param repoRef string = 'main'

@description('With imageSource "pull" from a private registry: the registry user name (empty for a public image).')
param registryUsername string = ''

@description('With imageSource "pull" from a private registry: the registry password or token (SECRET, a pull-only token is enough). Never an output.')
@secure()
param registryPassword string = ''

@description('Generate a test root CA and a server certificate for the FQDN on the first boot (recommended). Set to false to bring your own certificate: copy server.crt and server.key to /opt/ekmmock/data/tls on the VM and run "sudo /opt/ekmmock/bin/ekmmock-vm.sh run".')
param generateTestCertificate bool = true

@description('Start the container with EKMMOCK_ENABLE_FAULTS=true so that the console and CLI can inject delays, errors, HSM-offline and blackhole faults (needed for the spec 15 scenarios). Rules can only be created from the loopback-only console. Set to false for a quiet endpoint.')
param enableFaultInjection bool = true

@description('Type of the OS disk. StandardSSD_LRS is a cheap default; the data (key store, certificates, audit log) lives on this disk under /opt/ekmmock/data. Disks are encrypted at rest with platform-managed keys (the Azure default).')
@allowed([
  'Standard_LRS'
  'StandardSSD_LRS'
  'Premium_LRS'
])
param osDiskType string = 'StandardSSD_LRS'

@description('Size of the OS disk in GiB (the image build and the data folder live on it).')
@minValue(30)
@maxValue(1024)
param osDiskSizeGB int = 64

@description('Also encrypt the VM host cache and temporary disk (encryption at host). Needs the subscription feature Microsoft.Compute/EncryptionAtHost registered, so it is off by default. The OS disk is always encrypted at rest.')
param enableEncryptionAtHost bool = false

@description('Enable managed boot diagnostics (no storage account needed): serial console output for troubleshooting a boot that never finished.')
param enableBootDiagnostics bool = true

@description('Extra tags for every resource.')
param tags object = {}

// ---------------------------------------------------------------------------------------------------------------------------------
// Variables
// ---------------------------------------------------------------------------------------------------------------------------------

var suffix = uniqueString(resourceGroup().id)
var vmName = '${namePrefix}-vm-${take(suffix, 6)}'
var resourceTags = union(
  {
    application: 'ekmmock'
    purpose: 'test-only-simulator-not-an-hsm'
  },
  tags
)

// The public FQDN is known before the IP exists: <label>.<region>.cloudapp.azure.com (public Azure regions only; EKM is not available in sovereign clouds).
var fqdn = '${dnsLabel}.${location}.cloudapp.azure.com'

// Fail the deployment when the SSH source is open to the world (Bicep has no assert for deployments and no regex validator). When the value is "open", substring() is asked for more
// characters than the string has, which makes ARM reject the deployment ("The index and length parameters must refer to a location within the string"); otherwise it returns the trimmed address unchanged.
var sshSourceTrimmed = trim(allowedSshSourceAddress)
var sshSourceIsOpen = contains(
  [
    '*'
    '0.0.0.0'
    '0.0.0.0/0'
    '::/0'
    'internet'
    'any'
  ],
  toLower(sshSourceTrimmed)
)
var sshSourceChecked = substring(sshSourceTrimmed, 0, sshSourceIsOpen ? 100000 : length(sshSourceTrimmed))
// cloud-init document: every token in cloud-init.yaml is replaced by a BASE64 value, so a parameter can never inject YAML or shell. vm-setup.sh is the script they configure.
var cloudInitTokens = [
  { token: '@@FQDN@@', value: base64(fqdn) }
  { token: '@@IMAGE_SOURCE@@', value: base64(imageSource) }
  { token: '@@CONTAINER_IMAGE@@', value: base64(containerImage) }
  { token: '@@REPO_URL@@', value: base64(repoUrl) }
  { token: '@@REPO_REF@@', value: base64(repoRef) }
  { token: '@@GENERATE_CERTIFICATE@@', value: base64(generateTestCertificate ? 'true' : 'false') }
  { token: '@@ENABLE_FAULTS@@', value: base64(enableFaultInjection ? 'true' : 'false') }
  { token: '@@REGISTRY_USER@@', value: base64(registryUsername) }
  { token: '@@REGISTRY_PASSWORD@@', value: base64(registryPassword) }
  { token: '@@MASTER_KEY@@', value: base64(masterKey) }
  { token: '@@SETUP_SCRIPT@@', value: base64(loadTextContent('vm-setup.sh')) }
]
var cloudInit = reduce(
  cloudInitTokens,
  loadTextContent('cloud-init.yaml'),
  (document, item) => replace(document, item.token, item.value)
)
// ---------------------------------------------------------------------------------------------------------------------------------
// Network
// ---------------------------------------------------------------------------------------------------------------------------------

resource networkSecurityGroup 'Microsoft.Network/networkSecurityGroups@2025-05-01' = {
  name: '${namePrefix}-nsg-${suffix}'
  location: location
  tags: resourceTags
  properties: {
    securityRules: [
      {
        // The EKM endpoint. Managed HSM connects from IP addresses that are not static and cannot be allow-listed (no service tag exists either):
        // mutual TLS (client certificate CN + root CA allow-list in the app) is the access control, so this rule must be open to the internet.
        name: 'allow-ekm-https-443'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: 'Internet'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '443'
          description: 'EKM endpoint (mTLS in the app). Managed HSM IP addresses are not static.'
        }
      }
      {
        name: 'allow-ssh-from-operator'
        properties: {
          priority: 110
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: sshSourceChecked
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '22'
          description: 'SSH and the console tunnel (ssh -L 8080:127.0.0.1:8080), from the operator address only.'
        }
      }
      {
        // Explicit, so that the intent is visible in the template: nothing else comes in. The console port 8080 is NOT opened.
        name: 'deny-all-other-inbound'
        properties: {
          priority: 4096
          direction: 'Inbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
          description: 'Everything else, including the console port 8080.'
        }
      }
    ]
  }
}

resource virtualNetwork 'Microsoft.Network/virtualNetworks@2025-05-01' = {
  name: '${namePrefix}-vnet-${suffix}'
  location: location
  tags: resourceTags
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.42.0.0/24'
      ]
    }
  }
}

resource subnet 'Microsoft.Network/virtualNetworks/subnets@2025-05-01' = {
  parent: virtualNetwork
  name: 'ekmmock'
  properties: {
    addressPrefix: '10.42.0.0/27'
    networkSecurityGroup: {
      id: networkSecurityGroup.id
    }
  }
}

resource publicIpAddress 'Microsoft.Network/publicIPAddresses@2025-05-01' = {
  name: '${namePrefix}-pip-${suffix}'
  location: location
  tags: resourceTags
  sku: {
    name: 'Standard'
    tier: 'Regional'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
    publicIPAddressVersion: 'IPv4'
    dnsSettings: {
      domainNameLabel: dnsLabel
    }
  }
}

resource networkInterface 'Microsoft.Network/networkInterfaces@2025-05-01' = {
  name: '${namePrefix}-nic-${suffix}'
  location: location
  tags: resourceTags
  properties: {
    ipConfigurations: [
      {
        name: 'primary'
        properties: {
          privateIPAllocationMethod: 'Dynamic'
          subnet: {
            id: subnet.id
          }
          publicIPAddress: {
            id: publicIpAddress.id
            properties: {
              deleteOption: 'Delete'
            }
          }
        }
      }
    ]
  }
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Virtual machine
// ---------------------------------------------------------------------------------------------------------------------------------

resource virtualMachine 'Microsoft.Compute/virtualMachines@2025-04-01' = {
  name: vmName
  location: location
  tags: resourceTags
  properties: {
    hardwareProfile: {
      vmSize: vmSize
    }
    securityProfile: {
      encryptionAtHost: enableEncryptionAtHost
    }
    storageProfile: {
      imageReference: {
        // Ubuntu 24.04 LTS (Noble), the same distribution family as the container image (OpenSSL 3 for the TLS 1.3 cipher-suite policy).
        publisher: 'Canonical'
        offer: 'ubuntu-24_04-lts'
        sku: 'server'
        version: 'latest'
      }
      osDisk: {
        createOption: 'FromImage'
        caching: 'ReadWrite'
        diskSizeGB: osDiskSizeGB
        deleteOption: 'Delete'
        managedDisk: {
          // Platform-managed key encryption at rest (server-side encryption) is on by default for managed disks.
          storageAccountType: osDiskType
        }
      }
    }
    osProfile: {
      computerName: take(vmName, 63)
      adminUsername: adminUsername
      linuxConfiguration: {
        // SSH key login only.
        disablePasswordAuthentication: true
        ssh: {
          publicKeys: [
            {
              path: '/home/${adminUsername}/.ssh/authorized_keys'
              keyData: sshPublicKey
            }
          ]
        }
        provisionVMAgent: true
      }
      // cloud-init (custom data). Contains the master key as a secret: it is never returned by the API and never an output of this template.
      customData: base64(cloudInit)
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: networkInterface.id
          properties: {
            primary: true
            deleteOption: 'Delete'
          }
        }
      ]
    }
    diagnosticsProfile: {
      bootDiagnostics: {
        // Without storageUri this is MANAGED boot diagnostics.
        enabled: enableBootDiagnostics
      }
    }
  }
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Outputs (never a secret)
// ---------------------------------------------------------------------------------------------------------------------------------

@description('The public FQDN of the EKM endpoint: use it as --host of "az keyvault ekm-connection create". It is the SAN of the generated server certificate.')
output fqdn string = publicIpAddress.properties.dnsSettings.fqdn

@description('The static public IP address.')
output publicIpAddress string = publicIpAddress.properties.ipAddress

@description('The name of the virtual machine.')
output vmName string = virtualMachine.name

@description('SSH into the VM (from the address allowed by allowedSshSourceAddress).')
output sshCommand string = 'ssh ${adminUsername}@${publicIpAddress.properties.dnsSettings.fqdn}'

@description('Opens the console on your laptop at https://127.0.0.1:8080 (keep it running). The console is on the VM loopback only.')
output consoleTunnelCommand string = 'ssh -N -L 8080:127.0.0.1:8080 ${adminUsername}@${publicIpAddress.properties.dnsSettings.fqdn}'

@description('Copies the PUBLIC root CA certificate to your machine: pass this file as --server-ca-certificate. The private keys stay on the VM.')
output fetchRootCaCommand string = 'scp ${adminUsername}@${publicIpAddress.properties.dnsSettings.fqdn}:/opt/ekmmock/data/tls/root-ca.pem ./root-ca.pem'

@description('Where to watch the first-boot set-up on the VM.')
output bootstrapLogCommand string = 'ssh ${adminUsername}@${publicIpAddress.properties.dnsSettings.fqdn} sudo tail -f /var/log/ekmmock-bootstrap.log'
