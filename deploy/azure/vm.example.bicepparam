// EXAMPLE parameters for deploy/azure/vm.bicep. Copy to vm.local.bicepparam (git-ignored) and replace every <REPLACE-...> placeholder. Nothing secret belongs in this file.
//
//   export EKMMOCK_MASTER_KEY="$(openssl rand -base64 32)"        # PowerShell: $env:EKMMOCK_MASTER_KEY = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
//   az deployment group create --resource-group <rg> --template-file deploy/azure/vm.bicep --parameters deploy/azure/vm.local.bicepparam
//
// The master key is read from the environment variable at deployment time: it is neither in this file, nor on the command line, nor in your shell history.
// KEEP A COPY of it in a password manager or a Key Vault: losing it makes every key in the key store unrecoverable.
using './vm.bicep'

// The SAME region as your Managed HSM pool (for example 'westeurope').
param location = '<REPLACE-with-the-region-of-your-managed-hsm>'

// Optional: a fixed DNS label (the host name becomes <label>.<location>.cloudapp.azure.com). Omit the line to get 'ekmmock-<unique>'.
// param dnsLabel = '<REPLACE-optional-dns-label>'

// The PUBLIC key that may log in (cat ~/.ssh/id_ed25519.pub). Not a secret.
param sshPublicKey = '<REPLACE-with-your-ssh-PUBLIC-key-line-ssh-ed25519-AAAA-you@laptop>'

// Your public IP address or CIDR (for example from https://ifconfig.me). There is no default and '*' is rejected.
param allowedSshSourceAddress = '<REPLACE-with-your-public-ip-address>'

// Secret, from the environment (see above).
param masterKey = readEnvironmentVariable('EKMMOCK_MASTER_KEY')

// 'build' clones the repository on the VM and builds the image there (no image is published). Pin repoRef to a tag or a commit SHA for a reproducible deployment.
param imageSource = 'build'
param repoUrl = 'https://github.com/azureholic/ekmmock.git'
param repoRef = 'main'

// Alternative: your own registry.
// param imageSource = 'pull'
// param containerImage = '<REPLACE-registry>/ekmmock:<REPLACE-version>'
// param registryUsername = '<REPLACE-pull-token-name>'
// param registryPassword = readEnvironmentVariable('EKMMOCK_REGISTRY_PASSWORD')
