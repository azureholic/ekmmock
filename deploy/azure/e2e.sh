#!/usr/bin/env bash
# EkmMock end-to-end test against a real Azure Key Vault Managed HSM (spec section 15). Implements the flow and the scenarios whose results go into docs/RESULTS.md.
#
# ======================================================================================================================================================
#  UNVERIFIED AGAINST A REAL MANAGED HSM.  This script was written from the spec, Microsoft Learn and the installed Azure CLI's own --help output, and
#  was only executed with --dry-run (the commands it would run), bash -n and shellcheck. Nothing here has run against Azure yet. Read each step before you
#  run it for real, and expect to adjust it (az output shapes, role names, timing). Record what you find in docs/RESULTS.md and docs/OPEN-QUESTIONS.md.
# ======================================================================================================================================================
#
# It never deploys anything: deploy the VM first (deploy/azure/vm.bicep, see deploy/azure/README.md). It never prints a DEK (only its length and the
# first 12 hex characters of its SHA-256, the same fingerprint the EkmMock inspector shows), and it deletes the plaintext request bodies it writes.
#
# Needs: bash 5+, Azure CLI 2.x signed in (az login), openssl, curl, the `ekmmock` CLI (build src/EkmMock.Cli, or use the image's), and an SSH tunnel to the
# VM's loopback console:   ssh -N -L 8080:127.0.0.1:8080 <user>@<fqdn>     (keep it running in another terminal; the console is NOT exposed publicly).
#
# Quick start:
#   export HSM=<managed-hsm-name> FQDN=<proxy-fqdn>            # FQDN = the "fqdn" output of vm.bicep
#   scp <user>@$FQDN:/opt/ekmmock/data/tls/root-ca.pem ./root-ca.pem      # the PUBLIC root CA; the private keys stay on the VM
#   deploy/azure/e2e.sh --dry-run all           # prints every command, executes nothing
#   deploy/azure/e2e.sh all                     # prereqs, trust, connect, keys, roundtrip
#   deploy/azure/e2e.sh baseline                # then sweep, key-disable, key-destroy, offline, observe, and finally cleanup --yes
set -euo pipefail

if ((BASH_VERSINFO[0] < 5)); then
  echo "ERROR: bash 5 or newer is required (found ${BASH_VERSION}). On macOS: brew install bash." >&2
  exit 2
fi

# ---------------------------------------------------------------------------------------------------------------------------------
# Settings (environment variables or options; options win)
# ---------------------------------------------------------------------------------------------------------------------------------
HSM=${HSM:-}                                   # Managed HSM name (required)
FQDN=${FQDN:-}                                 # public FQDN of the EKM proxy: --host of the connection and the SAN of the server certificate (required)
PATH_PREFIX=${PATH_PREFIX:-}                   # optional path prefix such as /contoso/prod (needs a namespace with that prefix: created for you)
ROOT_CA=${ROOT_CA:-./root-ca.pem}              # public root CA certificate of the proxy's server certificate (--server-ca-certificate)
CONSOLE=${CONSOLE:-https://127.0.0.1:8080}    # the console through the SSH tunnel
CONSOLE_CA=${CONSOLE_CA:-}                     # PEM root CA that issued the console's certificate; default: ROOT_CA when it exists (its SAN includes 127.0.0.1 and localhost)
CONSOLE_INSECURE=${CONSOLE_INSECURE:-0}        # 1 = do not verify the console certificate (loopback only; the CLI refuses it for any other host)
EKMMOCK=${EKMMOCK:-ekmmock}                    # how to start the CLI, for example "dotnet src/EkmMock.Cli/bin/Debug/net10.0/ekmmock.dll"
EKMMOCK_CONSOLE_ARGS=${EKMMOCK_CONSOLE_ARGS:-} # extra console options for the CLI, for example "--auth entra --tenant <id> --client-id <id>" (ACI) ; a bearer token in $EKMMOCK_CONSOLE_TOKEN also works
WORK_DIR=${WORK_DIR:-./e2e-work}               # artifacts: mhsm-client.json, results/*.md, exports (all git-ignored)
AES_KEY=${AES_KEY:-aes-key-1}                  # external key identifiers in EkmMock (spec 11.2 sample keys)
RSA_KEY=${RSA_KEY:-rsa-key-1}
AES_REF=${AES_REF:-ekm-aes}                    # key reference names in Managed HSM
RSA_REF=${RSA_REF:-ekm-rsa}
AES_ALGS=${AES_ALGS:-A256KW}                   # algorithms for the round trip; add A256KWP to see how Managed HSM reacts to it
RSA_ALGS=${RSA_ALGS:-RSA-OAEP-256}
BASELINE_CALLS=${BASELINE_CALLS:-1000}         # spec 15: 1,000 unwraps
SWEEP_DELAYS=${SWEEP_DELAYS:-"50 100 150 200 240 260 300"}   # spec 15 latency sweep (ms)
SWEEP_CALLS=${SWEEP_CALLS:-20}                 # unwraps per injected delay
LAW_ID=${LAW_ID:-}                             # optional: Log Analytics workspace GUID: the Azure-side queries then run for you (needs the az log-analytics extension)
DRY_RUN=0

ALL_STEPS=(prereqs trust connect keys roundtrip)
FAULTS_TOUCHED=0
TRY_OUTPUT=''
TRY_STATUS=0
EKMMOCK_CMD=()
CONSOLE_ARGS=()
NS=_default

usage() {
  cat <<'EOF'
EkmMock end-to-end test against a real Azure Managed HSM (spec section 15).  UNVERIFIED against a real Managed HSM.

Usage: e2e.sh [options] <command> [command options]

Options (or the environment variable in brackets):
  --hsm <name>            Managed HSM name [HSM] (required)
  --fqdn <fqdn>           public FQDN of the EKM proxy, no scheme [FQDN] (required)
  --path-prefix </p/q>    optional path prefix, must start with "/" [PATH_PREFIX]
  --root-ca <file>        public root CA certificate of the proxy [ROOT_CA]            (default ./root-ca.pem)
  --console <url>         console URL through your SSH tunnel [CONSOLE]                (default https://127.0.0.1:8080)
  --console-ca <file>     root CA of the console certificate [CONSOLE_CA]              (default: the root CA)
  --insecure-console      do not verify the console certificate, loopback only [CONSOLE_INSECURE=1]
  --ekmmock <cmd>         how to start the ekmmock CLI [EKMMOCK]                       (default: ekmmock)
  --work-dir <dir>        where artifacts and results are written [WORK_DIR]           (default ./e2e-work)
  --dry-run               print every command, execute nothing (nothing is written, no Azure or console call is made)
  -h, --help              this text

Commands, in the order of spec section 15:
  prereqs       az signed in, feature Microsoft.KeyVault/MHSM_EKM registered, the ekm-connection command group, roles (best effort), the console reachable
  trust         step 1: az keyvault ekm-connection certificate show > mhsm-client.json, then ekmmock trust import into the namespace
  connect       step 2: az keyvault ekm-connection create (or update) with --host and the ROOT CA, then check (watch it in Live traffic)
  keys          step 3: create the sample keys in EkmMock if missing, then az keyvault key create --external-key-id (metadata calls arrive)
  roundtrip     step 4: wrapkey and unwrapkey through Managed HSM (api-version 7.5) with a random 32-byte DEK; compares fingerprints; never prints the DEK
  all           prereqs, trust, connect, keys, roundtrip
  baseline      scenario: 1,000 unwraps via Managed HSM; saves the EkmMock-side numbers and prints the Azure-side KQL
  sweep         scenario: inject 50, 100, 150, 200, 240, 260, 300 ms and record where Managed HSM starts failing
  key-disable   scenario: disable a key in EkmMock (wrap/unwrap through Managed HSM must fail), enable it again
  key-destroy   scenario: a THROW-AWAY key is created, registered, used and then destroyed in EkmMock (irreversible, only for that key)
  offline       scenario: "HSM offline" and "blackhole" faults: effect on ekm-connection check and on unwrap
  observe       scenario: what Azure actually sends (alg, DEK sizes, HTTP version, connection reuse, padded or not) from the inspector export
  cleanup       the documented order: key refs, then the connection, then EkmMock keys; needs --yes (move workloads off the key FIRST)
                  cleanup options: --yes  (confirm), --keep-ekmmock-keys

Every scenario appends a markdown snippet with what it measured to <work-dir>/results/<scenario>.md, to be copied into docs/RESULTS.md.
Needs an SSH tunnel to the console:  ssh -N -L 8080:127.0.0.1:8080 <user>@<fqdn>
EOF
}

# ---------------------------------------------------------------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------------------------------------------------------------
say() { printf '%s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

# quote_cmd <args...>: the command as one line, quoting only the arguments that need it (so that the printed line can be pasted into a shell).
quote_cmd() {
  local out='' arg
  for arg in "$@"; do
    if [[ $arg =~ ^[A-Za-z0-9_@%+=:,./-]+$ ]]; then
      out+="$arg "
    else
      out+="'${arg//\'/\'\\\'\'}' "
    fi
  done
  printf '%s' "${out% }"
}

# run <cmd...>: print the command, execute it unless --dry-run.
run() {
  printf '+ %s\n' "$(quote_cmd "$@")" >&2
  if ((DRY_RUN)); then return 0; fi
  "$@"
}

# run_to_file <file> <cmd...>: like run, standard output goes to <file>.
run_to_file() {
  local file=$1
  shift
  printf '+ %s > %s\n' "$(quote_cmd "$@")" "$file" >&2
  if ((DRY_RUN)); then return 0; fi
  "$@" >"$file"
}

# run_capture <fake value for --dry-run> <cmd...>: prints the command to stderr, the command's output (or the fake value) to stdout.
run_capture() {
  local fake=$1
  shift
  printf '+ %s\n' "$(quote_cmd "$@")" >&2
  if ((DRY_RUN)); then
    printf '%s' "$fake"
    return 0
  fi
  "$@"
}

# try <cmd...>: run a command whose failure is part of the experiment. Sets TRY_STATUS and TRY_OUTPUT (stdout and stderr), never exits.
try() {
  printf '+ %s\n' "$(quote_cmd "$@")" >&2
  if ((DRY_RUN)); then
    TRY_STATUS='n/a'
    TRY_OUTPUT='[dry-run: not executed]'
    return 0
  fi
  if TRY_OUTPUT=$("$@" 2>&1); then TRY_STATUS=0; else TRY_STATUS=$?; fi
  return 0
}

first_line() { printf '%s' "$1" | sed -n '1p' | cut -c1-200; }

now_ms() {
  local t=${EPOCHREALTIME/./}
  printf '%s' $((t / 1000))
}

# record <scenario> <markdown line...>: append to the scenario's result file (printed instead in --dry-run).
record() {
  local scenario=$1
  shift
  if ((DRY_RUN)); then
    printf '[dry-run] would append to %s/results/%s.md: %s\n' "$WORK_DIR" "$scenario" "$*"
    return 0
  fi
  mkdir -p "$WORK_DIR/results"
  printf '%s\n' "$*" >>"$WORK_DIR/results/$scenario.md"
}

stamp() { date -u +%Y-%m-%dT%H:%M:%SZ; }

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

b64url_decode() {
  local s=${1//-/+}
  s=${s//_//}
  while ((${#s} % 4)); do s+='='; done
  printf '%s' "$s" | openssl base64 -d -A
}

# fingerprint <file>: the first 12 hex characters of the SHA-256 of the raw bytes: the fingerprint of the EkmMock inspector (spec 8.4).
fingerprint() { openssl dgst -sha256 -r "$1" | cut -c1-12; }

file_size() { wc -c <"$1" | tr -d ' '; }

cleanup_files() {
  if ((!DRY_RUN)) && [[ -d $WORK_DIR ]]; then
    rm -f "$WORK_DIR"/dek.bin "$WORK_DIR"/unwrapped.bin "$WORK_DIR"/wrap-*.json "$WORK_DIR"/unwrap-*.json 2>/dev/null || true
  fi
}

on_exit() {
  local code=$?
  if ((FAULTS_TOUCHED && !DRY_RUN)); then
    warn "removing the fault rules this script created"
    console_curl POST /api/console/faults/clear >/dev/null 2>&1 || warn "could not clear the fault rules: run 'ekmmock faults clear' yourself"
  fi
  cleanup_files
  exit "$code"
}

setup_cli() {
  # shellcheck disable=SC2206 # word splitting of $EKMMOCK is intended ("dotnet path/to/ekmmock.dll")
  EKMMOCK_CMD=($EKMMOCK)
  CONSOLE_ARGS=(--console "$CONSOLE")
  if [[ $CONSOLE_INSECURE == 1 ]]; then
    CONSOLE_ARGS+=(--insecure-console-cert)
  elif [[ -n $CONSOLE_CA ]]; then
    CONSOLE_ARGS+=(--console-ca "$CONSOLE_CA")
  fi
  if [[ -n $EKMMOCK_CONSOLE_ARGS ]]; then
    # shellcheck disable=SC2206
    CONSOLE_ARGS+=($EKMMOCK_CONSOLE_ARGS)
  fi
  if [[ -n $PATH_PREFIX ]]; then
    NS=$(printf '%s' "${PATH_PREFIX#/}" | tr '/' '-')
  fi
}

# ekm <ekmmock arguments...>: the ekmmock CLI against the console.
ekm() { run "${EKMMOCK_CMD[@]}" "$@" "${CONSOLE_ARGS[@]}"; }
ekm_capture() {
  local fake=$1
  shift
  run_capture "$fake" "${EKMMOCK_CMD[@]}" "$@" "${CONSOLE_ARGS[@]}"
}

# console_curl <METHOD> <path> [json body]: a direct call to the console API (needed for fault delays the CLI presets do not cover). Prints the response body.
console_curl() {
  local method=$1 path=$2 body=${3:-}
  local args=(--silent --show-error --fail-with-body --max-time 60 --request "$method" --header 'Accept: application/json')
  if [[ $CONSOLE_INSECURE == 1 ]]; then
    args+=(--insecure)
  elif [[ -n $CONSOLE_CA ]]; then
    args+=(--cacert "$CONSOLE_CA")
  fi
  if [[ -n ${EKMMOCK_CONSOLE_TOKEN:-} ]]; then
    args+=(--header "Authorization: Bearer ${EKMMOCK_CONSOLE_TOKEN}")
  else
    args+=(--header 'X-EkmMock-Client: ekmmock-cli')
  fi
  if [[ -n $body ]]; then
    args+=(--header 'Content-Type: application/json' --data "$body")
  fi
  # Headers (and so a bearer token) are deliberately not echoed.
  local shown=''
  if [[ -n $body ]]; then shown=" --data $body"; fi
  printf '+ curl --request %s %s%s%s\n' "$method" "$CONSOLE" "$path" "$shown" >&2
  if ((DRY_RUN)); then
    printf '{}'
    return 0
  fi
  curl "${args[@]}" "$CONSOLE$path"
}

# save_console <path> <file>: GET a console API path into a file (a warning when it fails; only printed in --dry-run).
save_console() {
  local path=$1 file=$2
  if ((DRY_RUN)); then
    printf '+ curl --request GET %s%s > %s\n' "$CONSOLE" "$path" "$file" >&2
    return 0
  fi
  console_curl GET "$path" >"$file" 2>/dev/null || warn "could not save $path"
}

fault_delay() {  FAULTS_TOUCHED=1
  console_curl POST /api/console/faults "{\"kind\":\"delay\",\"delay_ms\":$1,\"description\":\"e2e delay $1 ms\"}" >/dev/null
}
fault_kind() {
  FAULTS_TOUCHED=1
  console_curl POST /api/console/faults "{\"kind\":\"$1\",\"description\":\"e2e $1\"}" >/dev/null
}
faults_clear() { console_curl POST /api/console/faults/clear >/dev/null; }

require_settings() {
  [[ -n $HSM ]] || die "the Managed HSM name is required (--hsm or \$HSM)"
  [[ -n $FQDN ]] || die "the proxy FQDN is required (--fqdn or \$FQDN)"
  case $FQDN in
    *://* | */* | *:*) die "--fqdn must be a bare host name (no scheme, no port, no path): '$FQDN'" ;;
    *) ;;
  esac
  if [[ -n $PATH_PREFIX && $PATH_PREFIX != /* ]]; then die "--path-prefix must start with '/': '$PATH_PREFIX'"; fi
  if [[ -z $CONSOLE_CA && -f $ROOT_CA ]]; then CONSOLE_CA=$ROOT_CA; fi
}

mhsm_uri() { printf 'https://%s.managedhsm.azure.net/keys/%s/%s?api-version=7.5' "$HSM" "$1" "$2"; }

# mhsm_call <key ref> <wrapkey|unwrapkey> <body file>: the data-plane call of spec 15 step 4; prints the "value" of the response.
mhsm_call() {
  az rest --method POST --resource https://managedhsm.azure.net --uri "$(mhsm_uri "$1" "$2")" \
    --headers Content-Type=application/json --body "@$3" --query value --output tsv
}

write_body() {
  local alg=$1 value=$2 file=$3
  printf '+ write {"alg":"%s","value":"<%s>"} to %s (mode 600)\n' "$alg" "$4" "$file" >&2
  if ((DRY_RUN)); then return 0; fi
  (
    umask 077
    printf '{"alg":"%s","value":"%s"}\n' "$alg" "$value" >"$file"
  )
}

ensure_work_dir() {
  if ((DRY_RUN)); then
    printf '+ mkdir -p %s\n' "$WORK_DIR" >&2
  else
    mkdir -p "$WORK_DIR/results"
  fi
}

new_dek() {
  run openssl rand -out "$WORK_DIR/dek.bin" 32
  if ((!DRY_RUN)); then chmod 600 "$WORK_DIR/dek.bin"; fi
}

# ---------------------------------------------------------------------------------------------------------------------------------
# Step 0: prerequisites
# ---------------------------------------------------------------------------------------------------------------------------------
cmd_prereqs() {
  step "prerequisites (spec 15)"
  local tool
  for tool in az openssl curl; do
    if command -v "$tool" >/dev/null 2>&1; then say "ok: $tool found"; else die "$tool is not installed"; fi
  done
  if ((DRY_RUN)); then
    say "[dry-run] the checks below only print what would be run"
    run az account show --query '{subscription:id,user:user.name}' --output tsv
    run az feature show --namespace Microsoft.KeyVault --name MHSM_EKM --query properties.state --output tsv
    run az keyvault ekm-connection --help
    check_roles
    console_curl GET /api/console/status >/dev/null
    return 0
  fi

  run az account show --query '{subscription:id,user:user.name}' --output tsv
  say "Public Azure regions only (EKM excludes Azure Government and Azure China)."

  local state
  state=$(run_capture Registered az feature show --namespace Microsoft.KeyVault --name MHSM_EKM --query properties.state --output tsv)
  if [[ $state == Registered ]]; then
    say "ok: feature Microsoft.KeyVault/MHSM_EKM is Registered"
  else
    die "feature Microsoft.KeyVault/MHSM_EKM is '$state', not Registered. Register it: az feature register --namespace Microsoft.KeyVault --name MHSM_EKM (then wait)"
  fi

  # The ekm-connection command group exists in Azure CLI 2.92 (create, check, show, update, delete, certificate show). Learn's troubleshooting page also mentions
  # 'ekm-connection list', which this CLI version does not have: this script uses 'show' (docs/OPEN-QUESTIONS.md).
  run az keyvault ekm-connection --help >/dev/null || die "this Azure CLI has no 'az keyvault ekm-connection' group: az upgrade (or az extension add --name keyvault)"

  check_roles
  check_console
}

# Best effort: roles assigned to a GROUP the user belongs to are not detected, so a miss is a warning, not a failure.
check_roles() {
  local oid admin_id user_id assigned
  oid=$(run_capture 00000000-0000-0000-0000-000000000000 az ad signed-in-user show --query id --output tsv) || {
    warn "cannot read the signed-in user's object id (service principal?); check the roles yourself"
    return 0
  }
  admin_id=$(run_capture admin-role-id az keyvault role definition list --hsm-name "$HSM" --query "[?roleName=='Managed HSM EKM Administrator'].name | [0]" --output tsv) || admin_id=''
  user_id=$(run_capture user-role-id az keyvault role definition list --hsm-name "$HSM" --query "[?roleName=='Managed HSM Crypto User'].name | [0]" --output tsv) || user_id=''
  assigned=$(run_capture "$admin_id $user_id" az keyvault role assignment list --hsm-name "$HSM" --assignee-object-id "$oid" --query '[].roleDefinitionId' --output tsv) || assigned=''
  if ((DRY_RUN)); then return 0; fi
  local role id
  for role in "Managed HSM EKM Administrator:$admin_id" "Managed HSM Crypto User:$user_id"; do
    id=${role##*:}
    if [[ -z $id ]]; then
      warn "could not resolve the role definition '${role%%:*}' (CLI output differs?): check it yourself"
    elif [[ $assigned == *"$id"* ]]; then
      say "ok: ${role%%:*} is assigned to you"
    else
      warn "${role%%:*} was not found in your direct role assignments (a group assignment is not detected)"
    fi
  done
}

check_console() {
  local status
  status=$(console_curl GET /api/console/status 2>/dev/null) || {
    warn "the console at $CONSOLE did not answer. Is the SSH tunnel running?   ssh -N -L 8080:127.0.0.1:8080 <user>@$FQDN"
    return 0
  }
  say "ok: the console answered ($(first_line "$status" | cut -c1-80)...)"
}

# ---------------------------------------------------------------------------------------------------------------------------------
# Step 1: trust the Managed HSM client identity
# ---------------------------------------------------------------------------------------------------------------------------------
ensure_namespace() {
  [[ $NS == _default ]] && return 0
  local listing
  listing=$(ekm_capture "$NS" ns list --output json 2>/dev/null) || listing=''
  if [[ $listing == *"\"$NS\""* ]]; then
    say "namespace $NS exists"
  else
    ekm ns create --name "$NS" --prefix "${PATH_PREFIX#/}"
  fi
}

cmd_trust() {
  step "1. trust the Managed HSM client identity (spec 15 step 1)"
  require_settings
  ensure_work_dir
  run_to_file "$WORK_DIR/mhsm-client.json" az keyvault ekm-connection certificate show --hsm-name "$HSM"
  ensure_namespace
  say "Preview first (the CLI's own --dry-run: nothing is saved):"
  ekm trust import --ns "$NS" --json "$WORK_DIR/mhsm-client.json" --dry-run
  ekm trust import --ns "$NS" --json "$WORK_DIR/mhsm-client.json"
  say "Trust is by subject CN and root CA, never by fingerprint: after Microsoft rotates the client certificate nothing changes as long as CN and caCertificates do."
  say "Watch the caCertificates weekly (docs/RUNBOOK.md): re-run this step when they change."
}

# ---------------------------------------------------------------------------------------------------------------------------------
# Step 2: the connection
# ---------------------------------------------------------------------------------------------------------------------------------
cmd_connect() {
  step "2. create the EKM connection (spec 15 step 2)"
  require_settings
  if [[ ! -f $ROOT_CA ]]; then
    if ((DRY_RUN)); then
      warn "(dry-run) root CA file '$ROOT_CA' does not exist yet"
    else
      die "root CA file '$ROOT_CA' not found: scp <user>@$FQDN:/opt/ekmmock/data/tls/root-ca.pem $ROOT_CA"
    fi
  fi
  say "The root CA (not the leaf) goes to --server-ca-certificate; the host must be the certificate's SAN; the proxy must listen on TCP 443."
  local verb=create existing=''
  if ((!DRY_RUN)) && existing=$(az keyvault ekm-connection show --hsm-name "$HSM" --output tsv --query host 2>/dev/null) && [[ -n $existing ]]; then
    verb=update
    say "A connection to '$existing' exists: updating it instead of creating one (a pool has exactly one connection)."
  elif ((DRY_RUN)); then
    say "(dry-run) 'create' is shown; the real run uses 'update' when a connection already exists"
  fi
  local args=(az keyvault ekm-connection "$verb" --hsm-name "$HSM" --host "$FQDN" --server-ca-certificate "$ROOT_CA")
  if [[ -n $PATH_PREFIX ]]; then args+=(--path-prefix "$PATH_PREFIX"); fi
  run "${args[@]}"
  say "Check: Managed HSM calls the proxy's /info over mTLS. Watch it arrive in the console's Live traffic and Connections pages."
  run az keyvault ekm-connection check --hsm-name "$HSM"
}

# ---------------------------------------------------------------------------------------------------------------------------------
# Step 3: external key references
# ---------------------------------------------------------------------------------------------------------------------------------
ensure_ekmmock_key() {
  local name=$1 type=$2
  if ((!DRY_RUN)) && "${EKMMOCK_CMD[@]}" key show --ns "$NS" --name "$name" "${CONSOLE_ARGS[@]}" >/dev/null 2>&1; then
    say "key $name exists in namespace $NS"
  else
    ekm key create --ns "$NS" --name "$name" --type "$type"
  fi
}

ensure_key_reference() {
  local ref=$1 external=$2
  if ((!DRY_RUN)) && az keyvault key show --hsm-name "$HSM" --name "$ref" >/dev/null 2>&1; then
    say "key reference $ref exists in $HSM (the external key id is immutable per version; not creating another version)"
    return 0
  fi
  run az keyvault key create --hsm-name "$HSM" --name "$ref" --external-key-id "$external"
}

cmd_keys() {
  step "3. external key references (spec 15 step 3)"
  require_settings
  ensure_ekmmock_key "$AES_KEY" aes
  ensure_ekmmock_key "$RSA_KEY" rsa
  say "Registering references: Managed HSM calls /metadata for each (watch it in Live traffic)."
  ensure_key_reference "$AES_REF" "$AES_KEY"
  ensure_key_reference "$RSA_REF" "$RSA_KEY"
}

# ---------------------------------------------------------------------------------------------------------------------------------
# Step 4: wrap / unwrap round trip through Managed HSM
# ---------------------------------------------------------------------------------------------------------------------------------
roundtrip_one() {
  local ref=$1 alg=$2 tag=${2//[^A-Za-z0-9]/}
  say "-- $ref / $alg"
  new_dek
  local dek_b64u='' fp='' length=''
  if ((!DRY_RUN)); then
    dek_b64u=$(b64url <"$WORK_DIR/dek.bin")
    fp=$(fingerprint "$WORK_DIR/dek.bin")
    length=$(file_size "$WORK_DIR/dek.bin")
  fi
  write_body "$alg" "$dek_b64u" "$WORK_DIR/wrap-$tag.json" "base64url of a random 32-byte DEK"
  local wrapped
  wrapped=$(run_capture "<wrapped-value>" az rest --method POST --resource https://managedhsm.azure.net \
    --uri "$(mhsm_uri "$ref" wrapkey)" --headers Content-Type=application/json --body "@$WORK_DIR/wrap-$tag.json" --query value --output tsv) || die "wrapkey failed for $ref ($alg)"
  write_body "$alg" "$wrapped" "$WORK_DIR/unwrap-$tag.json" "the wrapped value from the previous step"
  local unwrapped
  unwrapped=$(run_capture "<unwrapped-value>" az rest --method POST --resource https://managedhsm.azure.net \
    --uri "$(mhsm_uri "$ref" unwrapkey)" --headers Content-Type=application/json --body "@$WORK_DIR/unwrap-$tag.json" --query value --output tsv) || die "unwrapkey failed for $ref ($alg)"
  if ((DRY_RUN)); then
    say "[dry-run] would compare the unwrapped value with the original DEK and print only its length and SHA-256 fingerprint"
    return 0
  fi
  b64url_decode "$unwrapped" >"$WORK_DIR/unwrapped.bin"
  chmod 600 "$WORK_DIR/unwrapped.bin"
  if cmp -s "$WORK_DIR/dek.bin" "$WORK_DIR/unwrapped.bin"; then
    say "PASS: $ref $alg: the unwrapped DEK equals the original ($length bytes, fingerprint $fp; the console shows the same fingerprint on the wrapkey request and the unwrapkey response)"
    record roundtrip "| $ref | $alg | $length | $fp | PASS | $(stamp) |"
  else
    say "FAIL: $ref $alg: the unwrapped DEK differs from the original (original fp $fp, returned fp $(fingerprint "$WORK_DIR/unwrapped.bin"))"
    record roundtrip "| $ref | $alg | $length | $fp | FAIL | $(stamp) |"
    return 1
  fi
  # Keep a wrapped value for the scenarios that need one (it is ciphertext, not a secret).
  printf '%s' "$wrapped" >"$WORK_DIR/wrapped-$tag.txt"
}

cmd_roundtrip() {
  step "4. wrapkey / unwrapkey through Managed HSM (spec 15 step 4, data plane api-version 7.5)"
  require_settings
  ensure_work_dir
  record roundtrip "| key ref | alg | DEK bytes | fingerprint | result | time (UTC) |"
  record roundtrip "|---|---|---|---|---|---|"
  local alg failed=0
  for alg in $AES_ALGS; do roundtrip_one "$AES_REF" "$alg" || failed=1; done
  for alg in $RSA_ALGS; do roundtrip_one "$RSA_REF" "$alg" || failed=1; done
  return "$failed"
}

# ---------------------------------------------------------------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------------------------------------------------------------

# prepare_unwrap <ref> <alg> <tag>: wraps a fresh DEK once and writes the unwrap body $WORK_DIR/unwrap-<tag>.json; the wrapped value is ciphertext.
prepare_unwrap() {
  local ref=$1 alg=$2 tag=$3 dek_b64u=''
  new_dek
  if ((!DRY_RUN)); then dek_b64u=$(b64url <"$WORK_DIR/dek.bin"); fi
  write_body "$alg" "$dek_b64u" "$WORK_DIR/wrap-$tag.json" "base64url of a random 32-byte DEK"
  local wrapped
  wrapped=$(run_capture "<wrapped-value>" az rest --method POST --resource https://managedhsm.azure.net --uri "$(mhsm_uri "$ref" wrapkey)" \
    --headers Content-Type=application/json --body "@$WORK_DIR/wrap-$tag.json" --query value --output tsv) || die "could not wrap a DEK with $ref"
  write_body "$alg" "$wrapped" "$WORK_DIR/unwrap-$tag.json" "the wrapped value"
}

unwrap_try() {
  local ref=$1 tag=$2
  try az rest --method POST --resource https://managedhsm.azure.net --uri "$(mhsm_uri "$ref" unwrapkey)" \
    --headers Content-Type=application/json --body "@$WORK_DIR/unwrap-$tag.json" --query value --output none
}

azure_side_kql() {
  cat <<'EOF'
// Managed HSM audit records of the EKM operations (Learn: Logging and monitoring for Managed HSM external key management)
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where OperationName in ("EkmWrapKey", "EkmUnwrapKey", "EkmGetKeyMetadata")
| where TimeGenerated > ago(2h)
| summarize calls = count(), failures = countif(ResultType != "Success"), p50 = percentile(DurationMs, 50), p95 = percentile(DurationMs, 95), p99 = percentile(DurationMs, 99) by OperationName, bin(TimeGenerated, 5m)
| order by TimeGenerated desc
EOF
}

run_azure_kql() {
  if [[ -n $LAW_ID ]]; then
    run az monitor log-analytics query --workspace "$LAW_ID" --analytics-query "$(azure_side_kql)" --output table || warn "the Log Analytics query failed (az extension add --name log-analytics?)"
  else
    say "Azure side: run this in the Log Analytics workspace of the Managed HSM diagnostic setting (or set LAW_ID=<workspace guid> to run it from here):"
    azure_side_kql
  fi
}

cmd_baseline() {
  step "scenario: baseline, $BASELINE_CALLS unwraps via Managed HSM (spec 15)"
  require_settings
  ensure_work_dir
  prepare_unwrap "$AES_REF" "${AES_ALGS%% *}" baseline
  if ((DRY_RUN)); then
    say "[dry-run] would call unwrapkey $BASELINE_CALLS times (az rest, one call at a time) and count successes and failures"
  else
    local ok=0 failed=0 i first_error='' started finished
    started=$(now_ms)
    for ((i = 1; i <= BASELINE_CALLS; i++)); do
      unwrap_try "$AES_REF" baseline
      if ((TRY_STATUS == 0)); then ok=$((ok + 1)); else
        failed=$((failed + 1))
        [[ -n $first_error ]] || first_error=$(first_line "$TRY_OUTPUT")
      fi
      if ((i % 100 == 0)); then say "  $i of $BASELINE_CALLS done ($ok ok, $failed failed)"; fi
    done
    finished=$(now_ms)
    say "baseline: $ok ok, $failed failed in $(((finished - started) / 1000)) s (client wall time includes az CLI start-up, so it says nothing about proxy latency)"
    record baseline "| $(stamp) | $BASELINE_CALLS unwraps of $AES_REF | $ok ok / $failed failed | first error: ${first_error:-none} |"
  fi
  say "EkmMock side (server time per exchange, masked):"
  save_console /api/console/dashboard "$WORK_DIR/baseline-dashboard.json"
  save_console "/api/console/export?format=json&op=unwrapkey" "$WORK_DIR/baseline-exchanges.json"
  if ((!DRY_RUN)); then say "Saved $WORK_DIR/baseline-dashboard.json (p50/p95/p99 per operation) and $WORK_DIR/baseline-exchanges.json (timing.total_ms and timing.crypto_ms per exchange)."; fi
  say "Also scrape ${CONSOLE}/metrics (ekmmock_request_duration_seconds). Then compare with the Azure side: the difference is roughly network plus Managed HSM overhead."
  run_azure_kql
}

cmd_sweep() {
  step "scenario: latency sweep, injected delays: $SWEEP_DELAYS ms (spec 15)"
  require_settings
  ensure_work_dir
  say "Needs the server started with EKMMOCK_ENABLE_FAULTS=true (the VM template does by default). Each step injects one delay rule, runs $SWEEP_CALLS unwraps, removes the rule."
  prepare_unwrap "$AES_REF" "${AES_ALGS%% *}" sweep
  record sweep "| injected delay (ms) | unwraps ok / total | first Azure-side error | EkmMock exchanges (saved) |"
  record sweep "|---|---|---|---|"
  local delay i ok failed first_error
  for delay in $SWEEP_DELAYS; do
    faults_clear
    fault_delay "$delay"
    ok=0
    failed=0
    first_error=''
    if ((DRY_RUN)); then
      say "[dry-run] would run $SWEEP_CALLS unwraps with a ${delay} ms delay"
      continue
    fi
    for ((i = 1; i <= SWEEP_CALLS; i++)); do
      unwrap_try "$AES_REF" sweep
      if ((TRY_STATUS == 0)); then ok=$((ok + 1)); else
        failed=$((failed + 1))
        [[ -n $first_error ]] || first_error=$(first_line "$TRY_OUTPUT")
      fi
    done
    save_console "/api/console/exchanges?op=unwrapkey&limit=$SWEEP_CALLS" "$WORK_DIR/sweep-${delay}ms-exchanges.json"
    say "delay $delay ms: $ok ok / $failed failed ${first_error:+(first error: $first_error)}"
    record sweep "| $delay | $ok / $((ok + failed)) | ${first_error:-none} | sweep-${delay}ms-exchanges.json |"
  done
  faults_clear
  FAULTS_TOUCHED=0
  say "Note where Managed HSM starts failing and what the Azure-side error looks like (ResultType and ResultDescription in AzureDiagnostics for EkmUnwrapKey):"
  run_azure_kql
}

cmd_key_disable() {
  step "scenario: disable a key (spec 15)"
  require_settings
  ensure_work_dir
  prepare_unwrap "$AES_REF" "${AES_ALGS%% *}" disable
  say "Before: unwrap through Managed HSM works"
  unwrap_try "$AES_REF" disable
  say "  status $TRY_STATUS"
  ekm key disable --ns "$NS" --name "$AES_KEY"
  unwrap_try "$AES_REF" disable
  local while_disabled=$TRY_STATUS while_disabled_error
  while_disabled_error=$(first_line "$TRY_OUTPUT")
  say "While disabled: status $while_disabled ${while_disabled_error:+($while_disabled_error)}  (EkmMock answers 403 KeyDisabled; see how Managed HSM reports it)"
  ekm key enable --ns "$NS" --name "$AES_KEY"
  unwrap_try "$AES_REF" disable
  say "After enabling: status $TRY_STATUS"
  record key-disable "| $(stamp) | disabled: exit $while_disabled (${while_disabled_error:-none}) | re-enabled: exit $TRY_STATUS |"
  say "Effect on a CMK-protected Storage account and how long until it shows: do this by hand (RESULTS.md section 4): disable $AES_KEY, then read/write blobs and time it."
}

cmd_key_destroy() {
  step "scenario: destroy a key (irreversible, but only a throw-away key is destroyed)"
  require_settings
  ensure_work_dir
  local ek=e2e-destroy-key ref=ekm-e2e-destroy
  warn "This creates the throw-away key $ek, registers $ref, then DESTROYS $ek in EkmMock (crypto-shred). Your real keys are untouched."
  ensure_ekmmock_key "$ek" aes
  ensure_key_reference "$ref" "$ek"
  prepare_unwrap "$ref" "${AES_ALGS%% *}" destroy
  unwrap_try "$ref" destroy
  say "Before destroying: status $TRY_STATUS"
  ekm key destroy --ns "$NS" --name "$ek" --confirm "$ek"
  unwrap_try "$ref" destroy
  say "After destroying: status $TRY_STATUS $(first_line "$TRY_OUTPUT") (EkmMock answers 404 KeyNotFound)"
  record key-destroy "| $(stamp) | after destroy: exit $TRY_STATUS ($(first_line "$TRY_OUTPUT")) |"
  say "Clean the reference up: az keyvault key delete --hsm-name $HSM --name $ref  (and purge it if soft-delete retains it)"
}

cmd_offline() {
  step "scenario: HSM offline and blackhole (spec 15)"
  require_settings
  ensure_work_dir
  prepare_unwrap "$AES_REF" "${AES_ALGS%% *}" offline
  say "-- HSM offline: info and every operation answer 503 HsmUnavailable"
  faults_clear
  fault_kind offline
  try az keyvault ekm-connection check --hsm-name "$HSM"
  local check_status=$TRY_STATUS check_out
  check_out=$(first_line "$TRY_OUTPUT")
  say "ekm-connection check while offline: exit $check_status $check_out"
  unwrap_try "$AES_REF" offline
  say "unwrap while offline: exit $TRY_STATUS $(first_line "$TRY_OUTPUT")"
  record offline "| $(stamp) | offline | check exit $check_status (${check_out:-none}) | unwrap exit $TRY_STATUS ($(first_line "$TRY_OUTPUT")) |"
  faults_clear
  try az keyvault ekm-connection check --hsm-name "$HSM"
  say "after clearing the fault: check exit $TRY_STATUS (watch the dashboard heartbeat and the EkmProxyAvailability metric recover)"
  say "-- blackhole: the request is accepted and never answered (the hold is capped by Faults:BlackholeMaxHoldSeconds)"
  fault_kind blackhole
  local t0 t1
  t0=$(now_ms)
  try timeout 300 az keyvault ekm-connection check --hsm-name "$HSM"
  t1=$(now_ms)
  say "ekm-connection check with a blackhole: exit $TRY_STATUS after $(((t1 - t0) / 1000)) s $(first_line "$TRY_OUTPUT")"
  record offline "| $(stamp) | blackhole | check exit $TRY_STATUS after $(((t1 - t0) / 1000)) s ($(first_line "$TRY_OUTPUT")) | |"
  t0=$(now_ms)
  unwrap_try "$AES_REF" offline
  t1=$(now_ms)
  say "unwrap with a blackhole: exit $TRY_STATUS after $(((t1 - t0) / 1000)) s $(first_line "$TRY_OUTPUT")"
  record offline "| $(stamp) | blackhole | unwrap exit $TRY_STATUS after $(((t1 - t0) / 1000)) s | |"
  faults_clear
  FAULTS_TOUCHED=0
  say "The effect on a CMK-protected workload (how long until it is affected, what the service reports) has to be observed on that workload: see docs/RESULTS.md."
}

cmd_observe() {
  step "scenario: what Azure actually sends (from the inspector export, spec 15 and open questions 1-5, 10, 11)"
  require_settings
  ensure_work_dir
  local jsonl="$WORK_DIR/inspector-export.jsonl"
  save_console "/api/console/export?format=jsonl" "$jsonl"
  save_console /api/console/connections/statistics "$WORK_DIR/connection-statistics.json"
  if ((DRY_RUN)); then
    say "[dry-run] would summarise $jsonl: algorithms, DEK sizes, HTTP versions, ALPN, padding, requests per connection"
    return 0
  fi
  say "Exported (masked: bodies show lengths and fingerprints, never DEKs) to $jsonl. A rough summary (use jq or the console for the real analysis):"
  say "-- alg per request:"
  grep -o '"algorithm":"[A-Za-z0-9-]*"' "$jsonl" | sort | uniq -c || true
  say "-- DEK / ciphertext sizes in bytes of masked values:"
  grep -o '"bytes":[0-9]*' "$jsonl" | sort | uniq -c || true
  say "-- HTTP versions:"
  grep -o '"http_version":"[^"]*"' "$jsonl" | sort | uniq -c || true
  say "-- ALPN:"
  grep -o '"alpn":"[^"]*"' "$jsonl" | sort | uniq -c || true
  say "-- unwrapkey requests whose (non-secret) wrapped value ends in '=' (padded base64url):"
  grep -cE 'value\\":\\"[A-Za-z0-9_-]+=+\\"' "$jsonl" || true
  say "-- Content-Type values seen:"
  grep -oiE 'content-type[^}]{0,80}application/json[^"]*' "$jsonl" | sort | uniq -c | head -5 || true
  say "Connection reuse: requests per connection and open connections are in $WORK_DIR/connection-statistics.json and on the console's Connections page."
  record observe "| $(stamp) | export: $jsonl | see the console's Connections page and the summary above |"
}

cmd_cleanup() {
  step "cleanup (spec 15: move workloads off the key, key refs, connection, EkmMock keys, then the VM)"
  require_settings
  local confirm=0 keep_keys=0 arg
  for arg in "$@"; do
    case $arg in
      --yes) confirm=1 ;;
      --keep-ekmmock-keys) keep_keys=1 ;;
      *) die "unknown cleanup option '$arg'" ;;
    esac
  done
  warn "DESTRUCTIVE. Destroying a key, or losing the master key, makes data protected by it unrecoverable. Move every workload off these keys FIRST."
  if ((!confirm && !DRY_RUN)); then die "refusing to continue without --yes (after you moved the workloads away)"; fi
  local ref
  for ref in "$AES_REF" "$RSA_REF" ekm-e2e-destroy; do
    if ((DRY_RUN)) || az keyvault key show --hsm-name "$HSM" --name "$ref" >/dev/null 2>&1; then
      run az keyvault key delete --hsm-name "$HSM" --name "$ref"
    else
      say "key reference $ref does not exist: skipping"
    fi
  done
  run az keyvault ekm-connection delete --hsm-name "$HSM"
  if ((keep_keys)); then
    say "Keeping the EkmMock keys (--keep-ekmmock-keys)."
  else
    local key
    for key in "$AES_KEY" "$RSA_KEY" e2e-destroy-key; do
      if ((DRY_RUN)) || "${EKMMOCK_CMD[@]}" key show --ns "$NS" --name "$key" "${CONSOLE_ARGS[@]}" >/dev/null 2>&1; then
        ekm key destroy --ns "$NS" --name "$key" --confirm "$key"
      fi
    done
  fi
  say "Last: delete the VM and everything around it. This script does not know your resource group, so it prints the command:"
  say "  az group delete --name <resource-group> --yes --no-wait"
  say "Deleted Managed HSM keys stay soft-deleted for the retention period (az keyvault key purge needs purge permission and no purge protection)."
}

# ---------------------------------------------------------------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------------------------------------------------------------
main() {
  local command=''
  while (($#)); do
    case $1 in
      -h | --help) usage; exit 0 ;;
      --dry-run) DRY_RUN=1 ;;
      --hsm) HSM=${2:?--hsm needs a value}; shift ;;
      --fqdn) FQDN=${2:?--fqdn needs a value}; shift ;;
      --path-prefix) PATH_PREFIX=${2:?--path-prefix needs a value}; shift ;;
      --root-ca) ROOT_CA=${2:?--root-ca needs a value}; shift ;;
      --console) CONSOLE=${2:?--console needs a value}; shift ;;
      --console-ca) CONSOLE_CA=${2:?--console-ca needs a value}; shift ;;
      --insecure-console) CONSOLE_INSECURE=1 ;;
      --ekmmock) EKMMOCK=${2:?--ekmmock needs a value}; shift ;;
      --work-dir) WORK_DIR=${2:?--work-dir needs a value}; shift ;;
      -*) usage >&2; die "unknown option '$1'" ;;
      *) command=$1; shift; break ;;
    esac
    shift
  done
  [[ -n $command ]] || { usage >&2; exit 2; }

  trap on_exit EXIT
  if ((DRY_RUN)); then
    say "DRY RUN: the commands are printed with a leading '+', nothing is executed, nothing is written."
    [[ -n $HSM ]] || HSM='<managed-hsm-name>'
    [[ -n $FQDN ]] || FQDN='<proxy-fqdn>'
  fi
  require_settings
  setup_cli

  case $command in
    prereqs) cmd_prereqs ;;
    trust) cmd_trust ;;
    connect) cmd_connect ;;
    keys) cmd_keys ;;
    roundtrip) cmd_roundtrip ;;
    all)
      local s
      for s in "${ALL_STEPS[@]}"; do "cmd_$s"; done
      ;;
    baseline) cmd_baseline ;;
    sweep) cmd_sweep ;;
    key-disable) cmd_key_disable ;;
    key-destroy) cmd_key_destroy ;;
    offline) cmd_offline ;;
    observe) cmd_observe ;;
    cleanup) cmd_cleanup "$@" ;;
    *) usage >&2; die "unknown command '$command'" ;;
  esac
}

main "$@"
