# EkmMock container image (spec 11.1, 5.5). Build from the repository root:
#
#     docker build -f deploy/docker/Dockerfile -t ekmmock:dev .
#
# Stages: build (SDK, ReadyToRun publish of the server and the ekmmock CLI) -> runtime (ASP.NET on Ubuntu 24.04 with OpenSSL).
# The runtime base is deliberately NOT Alpine, distroless or chiseled: the EKM endpoint restricts the TLS 1.3 cipher suites through
# CipherSuitesPolicy, which needs OpenSSL (spec 3, 5.1). Both base images are pinned by tag AND digest (Dependabot's docker ecosystem keeps
# them current); the digest is the multi-architecture index of the tag at the time of writing.
#
# Secrets are never build arguments and never in a layer: the master key and the Entra client secret reach the container at run time only
# (EKMMOCK_MASTER_KEY_FILE / Docker secrets, see deploy/docker/compose.yaml). The build context is an allow-list (.dockerignore).

# ---------------------------------------------------------------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------------------------------------------------------------
FROM mcr.microsoft.com/dotnet/sdk:10.0-noble@sha256:212fe4cb74627d5adf9817a4088906ae3edff1bd853bb27565d4b46731efe61e AS build

# Where NuGet packages come from. Empty = the NuGet configuration of the SDK image (nuget.org): the normal, clean-network path.
# Only for networks that cannot reach nuget.org (a corporate package mirror, a local folder feed): --build-arg NUGET_SOURCE=<url or path>.
# It is a restore source only; it never ends up in the image.
ARG NUGET_SOURCE=
# The runtime identifier of the published binaries (the image is Linux; linux-arm64 for an ARM host).
ARG RID=linux-x64
ARG CONFIGURATION=Release

WORKDIR /src

# Restore layer: only the files that decide the package graph, so that a source change does not re-download packages.
COPY global.json Directory.Build.props Directory.Packages.props ./
COPY src/EkmMock.Crypto/EkmMock.Crypto.csproj src/EkmMock.Crypto/
COPY src/EkmMock.Pki/EkmMock.Pki.csproj src/EkmMock.Pki/
COPY src/EkmMock.Server/EkmMock.Server.csproj src/EkmMock.Server/
COPY src/EkmMock.Cli/EkmMock.Cli.csproj src/EkmMock.Cli/
# PublishReadyToRun must be set at restore time too: it adds the crossgen2 and runtime packs to the restore.
RUN set -eu; \
    source_args=""; \
    if [ -n "${NUGET_SOURCE}" ]; then source_args="--source ${NUGET_SOURCE}"; fi; \
    dotnet restore src/EkmMock.Server/EkmMock.Server.csproj -r "${RID}" -p:PublishReadyToRun=true ${source_args}; \
    dotnet restore src/EkmMock.Cli/EkmMock.Cli.csproj -r "${RID}" -p:PublishReadyToRun=true ${source_args}

COPY src/ src/
# Framework-dependent (the aspnet base image supplies the runtime), ReadyToRun (faster start: the 250 ms budget starts at the first request after a restart).
# Server GC comes from the project (ServerGarbageCollector) and is set again in the runtime stage.
RUN dotnet publish src/EkmMock.Server/EkmMock.Server.csproj -c "${CONFIGURATION}" -r "${RID}" --self-contained false \
        -p:PublishReadyToRun=true --no-restore -o /out/server \
 && dotnet publish src/EkmMock.Cli/EkmMock.Cli.csproj -c "${CONFIGURATION}" -r "${RID}" --self-contained false \
        -p:PublishReadyToRun=true --no-restore -o /out/cli \
 && find /out -name '*.pdb' -delete

# ---------------------------------------------------------------------------------------------------------------------------------
# runtime
# ---------------------------------------------------------------------------------------------------------------------------------
FROM mcr.microsoft.com/dotnet/aspnet:10.0-noble@sha256:1a48394b6f29d3a32c79d9edecd4abda0ecbe8776d567dbfc4590ed6979c740c AS runtime

ARG VERSION=0.2.0
ARG REVISION=unknown
LABEL org.opencontainers.image.title="EkmMock" \
      org.opencontainers.image.description="EkmMock: a software HSM and EKM proxy simulator for Azure Key Vault Managed HSM external key management. A test tool, not an HSM: never protect real data with it." \
      org.opencontainers.image.source="https://github.com/azureholic/ekmmock" \
      org.opencontainers.image.url="https://github.com/azureholic/ekmmock" \
      org.opencontainers.image.documentation="https://github.com/azureholic/ekmmock/tree/main/docs" \
      org.opencontainers.image.licenses="NOASSERTION" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.base.name="mcr.microsoft.com/dotnet/aspnet:10.0-noble"

WORKDIR /app
COPY --from=build --chown=root:root /out/server/ /app/
COPY --from=build --chown=root:root /out/cli/ /app/cli/

# The CLI on PATH (the apphost finds the shared runtime in /usr/share/dotnet). It is the health probe and the in-container test client.
RUN ln -s /app/cli/ekmmock /usr/local/bin/ekmmock \
 && mkdir -p /data \
 && chown 1654:1654 /data \
 && chmod 0750 /data

# Runtime settings.
#  - Server GC (spec 11.1; DECISIONS "M8: Benchmark", "M9: Image"): one heap per available core, so the ring buffer's promotion rate does not cause long pauses.
#  - Invariant globalization: no ICU in the image, nothing in the product depends on culture data (the project sets it too).
#  - DOTNET_EnableDiagnostics_IPC=0: no diagnostics socket in /tmp (the root file system is read-only).
#  - ASPNETCORE_HTTP_PORTS is cleared: the base image's default plain-HTTP :8080 listener would collide with the console port and EkmMock has no plain-HTTP mode;
#    the two HTTPS listeners come from Endpoints:Ekm:Url and Endpoints:Console:Url (appsettings.json) only.
#  - Data__Path: the single writable place (key store, namespaces, audit log, inspector files, certificates, data protection keys).
#  - EKMMOCK_CONSOLE: where the bundled CLI (and so the HEALTHCHECK) finds the console: the loopback address inside this container.
ENV DOTNET_gcServer=1 \
    DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1 \
    DOTNET_EnableDiagnostics_IPC=0 \
    ASPNETCORE_HTTP_PORTS= \
    ASPNETCORE_ENVIRONMENT=Production \
    Data__Path=/data \
    EKMMOCK_CONSOLE=https://127.0.0.1:8080

# Only /data is writable. Mount it as a volume; run the container with --read-only (and a tmpfs on /tmp if you want one).
VOLUME ["/data"]

# 8443: the EKM endpoint (mutual TLS 1.3; published as 443). 8080: the console (HTTPS; keep it on the host's loopback).
EXPOSE 8443 8080

# Non-root. APP_UID (1654) is defined by the base image.
USER $APP_UID

# Spec 11.1: the health check asks /healthz on the console port. The runtime image has no curl, so the bundled CLI does it. --insecure-console-cert is
# accepted only for a loopback URL: the probe talks to 127.0.0.1 inside this container's own network namespace, and /healthz answers {"status":"alive"} and nothing else.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["ekmmock", "health", "--insecure-console-cert"]

STOPSIGNAL SIGTERM
ENTRYPOINT ["dotnet", "/app/EkmMock.Server.dll"]
# Arguments go here, for example CMD ["--dev"] (a generated throw-away master key and certificate: local testing only).
CMD []
