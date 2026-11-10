#!/usr/bin/env bash
# EkmMock VM setup (deploy/azure/vm.bicep). cloud-init installs this file as /opt/ekmmock/bin/ekmmock-vm.sh and runs `ekmmock-vm.sh bootstrap` once on first boot.
# It is also the tool you use later on the VM:
#
#   sudo /opt/ekmmock/bin/ekmmock-vm.sh bootstrap   first-boot set-up (idempotent): Docker, image, test certificates, container
#   sudo /opt/ekmmock/bin/ekmmock-vm.sh run         (re)create the container from the current image and configuration
#   sudo /opt/ekmmock/bin/ekmmock-vm.sh upgrade     rebuild (or pull) the image, then (re)create the container
#   sudo /opt/ekmmock/bin/ekmmock-vm.sh status      container state and the certificate that is served
#   sudo /opt/ekmmock/bin/ekmmock-vm.sh reissue     issue a NEW server certificate under the SAME test root CA (the root registered on the Managed HSM stays valid), then restart
#
# Everything it needs comes from small files in /opt/ekmmock/config (written by cloud-init from the Bicep parameters, base64-encoded in transit, so a parameter value is never
# interpreted as shell or YAML) and from /opt/ekmmock/secrets (the master key; the optional registry password). Nothing here is a secret literal. Log: /var/log/ekmmock-bootstrap.log.
#
# THIS IS A SIMULATOR. The container it starts is a software HSM for testing Azure Managed HSM external key management. Never protect real data with it.
set -euo pipefail

readonly BASE=/opt/ekmmock
readonly CONFIG=$BASE/config
readonly DATA=$BASE/data
readonly SECRETS=$BASE/secrets
# The test root CA private key lives here: root-owned, mode 0400, and NEVER mounted into the container (the container user can read everything under $DATA). See reissue_certificate.
readonly PKI_PRIVATE=$BASE/pki-private
readonly SOURCE_DIR=$BASE/src
readonly CONTAINER_NAME=ekmmock
# The uid of the unprivileged user inside the image ($APP_UID of the .NET base image).
readonly APP_UID=1654
# Inspector memory bounds for the small VM (Standard_B2s, 4 GiB): the in-memory ring buffer holds at most 5000 exchanges AND about 64 MiB (estimated), the capture queue 2048 records.
# Defaults of the app are 10000 / 128 MiB / 4096 (docs/DECISIONS.md "Security review follow-up"). Anonymous internet traffic reaches the inspector, so these are bounded in bytes, not only in count.
readonly INSPECTOR_RING_BUFFER_SIZE=5000
readonly INSPECTOR_MAX_BYTES=67108864
readonly INSPECTOR_CHANNEL_CAPACITY=2048
# Docker's apt repository signing key, primary key fingerprint (https://docs.docker.com/engine/install/ubuntu/). The key is downloaded over TLS and refused unless it matches.
readonly DOCKER_GPG_FINGERPRINT=9DC858229FC7DD38854AE2D88D81803C0EBFCD88

log() { printf '%s ekmmock-vm: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
die() { log "ERROR: $*" >&2; exit 1; }

# One configuration value. cloud-init wrote it without a trailing newline.
cfg() { cat "$CONFIG/$1"; }

install_docker() {
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    log "Docker is already installed"
    return
  fi
  export DEBIAN_FRONTEND=noninteractive
  local apt_get=(apt-get -o DPkg::Lock::Timeout=600 -y)
  "${apt_get[@]}" update
  "${apt_get[@]}" install ca-certificates curl gnupg git openssl

  local key_file fingerprint codename
  key_file=$(mktemp)
  curl -fsSL --proto '=https' --tlsv1.2 https://download.docker.com/linux/ubuntu/gpg -o "$key_file"
  fingerprint=$(gpg --show-keys --with-colons "$key_file" | awk -F: '$1 == "fpr" { print $10; exit }')
  [ "$fingerprint" = "$DOCKER_GPG_FINGERPRINT" ] || die "the Docker repository key has the unexpected fingerprint '$fingerprint'; refusing to install it"
  install -m 0755 -d /etc/apt/keyrings
  gpg --dearmor --yes --output /etc/apt/keyrings/docker.gpg "$key_file"
  chmod a+r /etc/apt/keyrings/docker.gpg
  rm -f "$key_file"

  codename=$(awk -F= '$1 == "VERSION_CODENAME" { print $2 }' /etc/os-release)
  printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu %s stable\n' "$(dpkg --print-architecture)" "$codename" >/etc/apt/sources.list.d/docker.list
  "${apt_get[@]}" update
  "${apt_get[@]}" install docker-ce docker-ce-cli containerd.io docker-buildx-plugin
  systemctl enable --now docker
  log "Docker installed: $(docker --version)"
}

prepare_folders() {
  # The container user owns the data folder (key store, certificates, audit log). The master key is readable by that user only (mode 0400); Docker bind-mounts the file itself,
  # so the folder around it stays root-only.
  install -d -m 0750 -o "$APP_UID" -g "$APP_UID" "$DATA" "$DATA/tls"
  install -d -m 0700 -o root -g root "$SECRETS" "$PKI_PRIVATE"
  [ -f "$SECRETS/master.key" ] || die "the master key file $SECRETS/master.key is missing (the masterKey parameter of the template)"
  chown "$APP_UID:$APP_UID" "$SECRETS/master.key"
  chmod 0400 "$SECRETS/master.key"
  if [ -f "$SECRETS/registry-password" ]; then
    chown root:root "$SECRETS/registry-password"
    chmod 0400 "$SECRETS/registry-password"
  fi
}

registry_host() {
  # The registry part of an image reference; empty for Docker Hub short names such as "ekmmock:local" or "library/ekmmock".
  local image=$1 first
  first=${image%%/*}
  if [ "$first" != "$image" ]; then
    case $first in
      *.* | *:* | localhost) printf '%s' "$first" ;;
      *) ;;
    esac
  fi
}

pull_image() {
  local image=$1 user host
  user=$(cfg registry-user)
  host=$(registry_host "$image")
  if [ -n "$user" ]; then
    log "logging in to ${host:-Docker Hub} as the configured registry user"
    docker login --username "$user" --password-stdin ${host:+"$host"} <"$SECRETS/registry-password"
  fi
  log "pulling $image"
  docker pull "$image"
  if [ -n "$user" ]; then
    docker logout ${host:+"$host"} >/dev/null 2>&1 || true
  fi
}

build_image() {
  local image=$1 url ref revision
  url=$(cfg repo-url)
  ref=$(cfg repo-ref)
  case $url in https://*) ;; *) die "repoUrl must start with https://" ;; esac
  case $ref in -* | '') die "repoRef must not be empty or start with '-'" ;; \<*) die "repoRef is still the placeholder; choose a tag or a full commit SHA" ;; *) ;; esac
  log "building $image from $url at $ref (this takes a few minutes on a small VM)"
  rm -rf "$SOURCE_DIR"
  install -d -m 0755 "$SOURCE_DIR"
  git -C "$SOURCE_DIR" init --quiet
  git -C "$SOURCE_DIR" remote add origin "$url"
  # Works for a branch, a tag or a full commit SHA (GitHub allows fetching a SHA).
  git -C "$SOURCE_DIR" fetch --quiet --depth 1 origin "$ref"
  git -C "$SOURCE_DIR" checkout --quiet FETCH_HEAD
  revision=$(git -C "$SOURCE_DIR" rev-parse HEAD)
  log "building revision $revision"
  docker build -f "$SOURCE_DIR/deploy/docker/Dockerfile" --build-arg "REVISION=$revision" -t "$image" "$SOURCE_DIR"
}

prepare_image() {
  local source image
  source=$(cfg image-source)
  image=$(cfg container-image)
  case $source in
    build) build_image "$image" ;;
    pull) pull_image "$image" ;;
    *) die "imageSource must be 'build' or 'pull', not '$source'" ;;
  esac
}

# The CLI inside the image, with the same hardening as the server container. It gets ONE host folder, mounted at /pki and owned by the container user for the duration of the call;
# it is never given $DATA, and the folder is deleted afterwards (see work_folder / discard_work_folder).
ekmmock_cli() {
  local folder=$1
  shift
  docker run --rm --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges:true -v "$folder:/pki" --entrypoint ekmmock "$(cfg container-image)" "$@"
}

# A scratch folder for one CLI call: mode 0700, owned by the container user so that the non-root process in the container can write its output there.
work_folder() {
  local folder
  folder=$(mktemp -d "$BASE/work.XXXXXX")
  chown "$APP_UID:$APP_UID" "$folder"
  chmod 0700 "$folder"
  printf '%s' "$folder"
}

# Best effort: overwrite, then delete (the files are small; a copy-on-write file system or a snapshot can still hold older blocks, which is why the CA key is root-only in the first place).
discard_work_folder() {
  local folder=$1
  find "$folder" -type f -exec shred -u {} + 2>/dev/null || true
  rm -rf "$folder"
}

certificate_present() { [ -s "$DATA/tls/server.crt" ] && [ -s "$DATA/tls/server.key" ]; }

# Installs the server certificate (chain, key) a CLI call wrote to $1 into the folder the container reads.
install_server_certificate() {
  local folder=$1
  install -m 0640 -o "$APP_UID" -g "$APP_UID" "$folder/server.crt" "$DATA/tls/server.crt"
  install -m 0600 -o "$APP_UID" -g "$APP_UID" "$folder/server.key" "$DATA/tls/server.key"
}

# Older VMs kept the root CA key in $DATA/pki, which the container can read. Move it out (once) to the root-only folder; the copies of the server certificate there are removed too.
move_ca_key_out_of_data() {
  if [ -f "$DATA/pki/root-ca.key" ]; then
    if [ -f "$PKI_PRIVATE/root-ca.key" ]; then
      shred -u "$DATA/pki/root-ca.key" 2>/dev/null || rm -f "$DATA/pki/root-ca.key"
    else
      install -m 0400 -o root -g root "$DATA/pki/root-ca.key" "$PKI_PRIVATE/root-ca.key"
      shred -u "$DATA/pki/root-ca.key" 2>/dev/null || rm -f "$DATA/pki/root-ca.key"
    fi
    log "the root CA private key was moved out of $DATA to $PKI_PRIVATE (root only, not mounted into the container)"
  fi
  # The server key copy in pki/ is redundant (the container uses $DATA/tls); keep nothing extra that is secret next to it.
  if [ -f "$DATA/pki/server.key" ]; then
    shred -u "$DATA/pki/server.key" 2>/dev/null || rm -f "$DATA/pki/server.key"
  fi
}

generate_certificates() {
  local fqdn folder
  fqdn=$(cfg fqdn)
  if certificate_present; then
    log "a server certificate is already in $DATA/tls; keeping it"
    return
  fi
  if [ "$(cfg generate-certificate)" != true ]; then
    log "generateTestCertificate is false and there is no certificate yet: copy your PEM chain and key to $DATA/tls/server.crt and server.key (owner uid $APP_UID, key mode 0600), then run '$0 run'"
    return
  fi
  log "generating a test root CA and a server certificate for $fqdn (SAN: $fqdn, localhost, 127.0.0.1)"
  # The CA private key is written to a scratch folder, then moved to $PKI_PRIVATE (root, mode 0400) and NEVER placed under $DATA, which is mounted into (and readable by) the container.
  # It stays on this VM so that '$0 reissue' can issue a new server certificate under the SAME root, which keeps the root registered on the Managed HSM connection valid.
  # Delete $PKI_PRIVATE/root-ca.key if you do not want that ability (then a new certificate means a new root and a new --server-ca-certificate).
  # localhost and 127.0.0.1 are extra SANs so that the console, reached through the SSH tunnel with the same certificate, verifies against root-ca.pem.
  folder=$(work_folder)
  ekmmock_cli "$folder" certs ca --out /pki
  ekmmock_cli "$folder" certs server --ca /pki/root-ca.pem --ca-key /pki/root-ca.key --fqdn "$fqdn" --san localhost --san 127.0.0.1 --out /pki
  install -m 0400 -o root -g root "$folder/root-ca.key" "$PKI_PRIVATE/root-ca.key"
  install_server_certificate "$folder"
  # root-ca.pem (public) is what the console's Certificates page offers for download and what 'az keyvault ekm-connection create --server-ca-certificate' takes.
  install -m 0644 -o "$APP_UID" -g "$APP_UID" "$folder/root-ca.pem" "$DATA/tls/root-ca.pem"
  discard_work_folder "$folder"
  log "root CA certificate (public): $DATA/tls/root-ca.pem (what 'az keyvault ekm-connection create --server-ca-certificate' takes)"
}

# Issues a new server certificate for the FQDN under the existing test root CA and restarts the container. Needs the CA key in $PKI_PRIVATE (it is not in $DATA; the container cannot see it).
reissue_certificate() {
  local fqdn folder
  fqdn=$(cfg fqdn)
  [ -s "$PKI_PRIVATE/root-ca.key" ] || die "there is no root CA key in $PKI_PRIVATE (it was deleted, or the certificate is not a generated one); issue a new root with a new VM or bring your own certificate"
  [ -s "$DATA/tls/root-ca.pem" ] || die "there is no $DATA/tls/root-ca.pem to issue under"
  log "issuing a new server certificate for $fqdn under the existing test root CA"
  folder=$(work_folder)
  install -m 0644 -o "$APP_UID" -g "$APP_UID" "$DATA/tls/root-ca.pem" "$folder/root-ca.pem"
  install -m 0400 -o "$APP_UID" -g "$APP_UID" "$PKI_PRIVATE/root-ca.key" "$folder/root-ca.key"
  ekmmock_cli "$folder" certs server --ca /pki/root-ca.pem --ca-key /pki/root-ca.key --fqdn "$fqdn" --san localhost --san 127.0.0.1 --out /pki
  install_server_certificate "$folder"
  discard_work_folder "$folder"
  run_container
}
run_container() {
  local image fqdn faults
  image=$(cfg container-image)
  fqdn=$(cfg fqdn)
  faults=$(cfg enable-faults)
  certificate_present || die "no server certificate in $DATA/tls (server.crt and server.key); the container would not start"
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  log "starting the container from $image"
  # The same hardening as deploy/docker/compose.yaml: read-only root file system (only /data and a tmpfs /tmp are writable), no capabilities, no privilege escalation, the image's own
  # non-root user (no --user), restart after a reboot, the image's HEALTHCHECK.
  #   --publish 443:8443              the EKM endpoint: TLS 1.3 and mutual TLS terminate in the app (Managed HSM needs 443; there is no TLS-terminating front end)
  #   --publish 127.0.0.1:8080:8080   the console, on the VM's LOOPBACK only (reach it with: ssh -L 8080:127.0.0.1:8080). NEVER publish it on 0.0.0.0: it is an unauthenticated admin UI.
  #   EKMMOCK_CONSOLE_CONTAINER_PUBLISH=true  the explicit opt-in that lets the console listen on the container's own address so that the loopback publish works (docs/DECISIONS.md)
  docker run --detach --name "$CONTAINER_NAME" --restart unless-stopped \
    --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges:true \
    --publish 443:8443 --publish 127.0.0.1:8080:8080 \
    --volume "$DATA:/data" \
    --volume "$SECRETS/master.key:/run/secrets/ekmmock_master_key:ro" \
    --env EKMMOCK_MASTER_KEY_FILE=/run/secrets/ekmmock_master_key \
    --env Tls__CertFile=/data/tls/server.crt --env Tls__KeyFile=/data/tls/server.key --env "Tls__ServerName=$fqdn" \
    --env Endpoints__Console__Url=https://0.0.0.0:8080 --env EKMMOCK_CONSOLE_CONTAINER_PUBLISH=true \
    --env "EKMMOCK_ENABLE_FAULTS=$faults" --env EKMMOCK_ALLOW_KEY_IMPORT=false \
    --env "Inspector__RingBufferSize=$INSPECTOR_RING_BUFFER_SIZE" --env "Inspector__MaxBytes=$INSPECTOR_MAX_BYTES" --env "Inspector__ChannelCapacity=$INSPECTOR_CHANNEL_CAPACITY" \
    "$image" >/dev/null
  wait_until_ready
}

wait_until_ready() {
  local attempt
  for attempt in $(seq 1 90); do
    if docker exec "$CONTAINER_NAME" ekmmock health --ready --insecure-console-cert >/dev/null 2>&1; then
      log "EkmMock is ready (after about $attempt s)"
      return
    fi
    sleep 1
  done
  docker logs --tail 40 "$CONTAINER_NAME" >&2 || true
  die "EkmMock did not become ready within 90 s (see: docker logs $CONTAINER_NAME)"
}

status() {
  docker ps --all --filter "name=^${CONTAINER_NAME}\$" --format 'container {{.Names}}: {{.Status}} (image {{.Image}})'
  if certificate_present; then
    openssl x509 -in "$DATA/tls/server.crt" -noout -subject -issuer -enddate -ext subjectAltName
  else
    log "no server certificate in $DATA/tls yet"
  fi
}

bootstrap() {
  log "bootstrap starts"
  prepare_folders
  move_ca_key_out_of_data
  install_docker
  if docker image inspect "$(cfg container-image)" >/dev/null 2>&1; then
    log "image $(cfg container-image) is already present"
  else
    prepare_image
  fi
  generate_certificates
  if certificate_present; then
    run_container
  fi
  log "bootstrap finished"
}

main() {
  [ "$(id -u)" -eq 0 ] || die "run as root (sudo)"
  case ${1:-help} in
    bootstrap) bootstrap ;;
    run) prepare_folders; move_ca_key_out_of_data; run_container ;;
    upgrade) prepare_folders; move_ca_key_out_of_data; prepare_image; run_container ;;
    reissue) prepare_folders; move_ca_key_out_of_data; reissue_certificate ;;
    status) status ;;
    *) sed -n '2,9p' "$0" ;;
  esac
}

# Sourcing this file (for tests) defines the functions without running anything.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
