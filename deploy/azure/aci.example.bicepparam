// EXAMPLE parameters for deploy/azure/aci.bicep (the ALTERNATIVE to the VM). Copy to aci.local.bicepparam (git-ignored) and replace every <REPLACE-...> placeholder.
// Nothing secret belongs in this file: secrets come from environment variables or files at deployment time.
//
//   export EKMMOCK_MASTER_KEY="$(openssl rand -base64 32)"
//   export EKMMOCK_ENTRA_CLIENT_SECRET="<the client secret of the app registration>"        # read -rs EKMMOCK_ENTRA_CLIENT_SECRET keeps it out of your shell history
//   export EKMMOCK_SERVER_CERT_FILE=../../out/pki/server.crt EKMMOCK_SERVER_KEY_FILE=../../out/pki/server.key     # paths are relative to THIS file, with "/" separators
//   az deployment group create --resource-group <rg> --template-file deploy/azure/aci.bicep --parameters deploy/azure/aci.local.bicepparam
//
// Read the limitations at the top of aci.bicep first: non-root binding of port 443 in ACI is UNVERIFIED, and ACI has no read-only root file system.
using './aci.bicep'

// The SAME region as your Managed HSM pool (for example 'westeurope').
param location = '<REPLACE-with-the-region-of-your-managed-hsm>'

// The host name becomes <label>.<location>.azurecontainer.io and must equal the SAN of the server certificate, so choose it BEFORE generating the certificate.
param dnsNameLabel = '<REPLACE-dns-label-lowercase-letters-digits-hyphens>'

// An image ACI can pull (build and push deploy/docker/Dockerfile to your registry first).
param containerImage = '<REPLACE-registry>/ekmmock:<REPLACE-version>'
// param imageRegistryCredentials = { server: '<REPLACE-registry>', username: '<REPLACE-pull-token-name>', password: readEnvironmentVariable('EKMMOCK_REGISTRY_PASSWORD') }

// Secrets, from the environment / files (never in this file).
param masterKey = readEnvironmentVariable('EKMMOCK_MASTER_KEY')
param entraClientSecret = readEnvironmentVariable('EKMMOCK_ENTRA_CLIENT_SECRET')
param serverCertificatePem = loadTextContent(readEnvironmentVariable('EKMMOCK_SERVER_CERT_FILE'))
param serverCertificateKeyPem = loadTextContent(readEnvironmentVariable('EKMMOCK_SERVER_KEY_FILE'))

// Entra ID sign-in of the console (second public port). Not secrets, but yours: replace the placeholders.
param entraTenantId = '<REPLACE-with-tenant-guid-xxxxxxxxx>'
param entraClientId = '<REPLACE-with-app-client-guid-xxxxx>'
param entraAllowedObjectIds = [
  '<REPLACE-with-the-object-id-guid-of-a-user-allowed-to-use-the-console>'
]
// param entraAllowedGroupId = '<REPLACE-optional-group-object-id-guid>'

// Last resort only, see aci.bicep: run as root if the non-root user cannot bind 443 in ACI.
// param runAsRoot = true
