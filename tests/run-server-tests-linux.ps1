<#
.SYNOPSIS
    Runs the EkmMock.Server tests on Linux (OpenSSL) inside a container, from a Windows (or any) host with Docker.

.DESCRIPTION
    Why: TLS cipher suite enforcement (spec 5.1) only works where the TLS stack supports CipherSuitesPolicy, which is Linux/OpenSSL
    (the production target). On Windows the four "Linux_*" cipher tests are skipped; this script runs the whole server test project on Linux so
    they execute.

    How: builds the solution on the host, copies the repository into the container and runs the already built, portable test output on the
    container's .NET runtime. It does not restore or build inside the container, so it works where the container cannot reach NuGet
    (it could not in the environment where milestone M3 was built). The Server project's content root is baked into the test assembly as a
    host path, so a stand-in directory with appsettings.json is created at that relative path inside the container.

.PARAMETER Image
    SDK or aspnet image with the .NET 10 runtime. Default mcr.microsoft.com/dotnet/sdk:10.0.

.PARAMETER NoBuild
    Skip the host build (use the existing bin output).

.PARAMETER TestArgs
    Extra arguments for the xUnit in-process runner, for example: -class EkmMock.Server.Tests.CipherPolicyTests
#>
[CmdletBinding()]
param(
    [string]$Image = 'mcr.microsoft.com/dotnet/sdk:10.0',
    [string]$Configuration = 'Debug',
    [switch]$NoBuild,
    [string]$TestArgs = ''
)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw 'docker was not found on PATH.'
}

$osType = (docker info --format '{{.OSType}}' 2>$null)
if ($osType -ne 'linux') {
    throw "The Docker engine is not running Linux containers (OSType='$osType'). Start Docker Desktop in Linux container mode."
}

if (-not $NoBuild) {
    dotnet build (Join-Path $repo 'EkmMock.sln') -c $Configuration -warnaserror
    if ($LASTEXITCODE -ne 0) { throw 'Build failed.' }
}

$stubRoot = Join-Path $repo 'src\EkmMock.Server'

# The script text must reach bash with LF line endings, or every line ends in a stray carriage return.
$inner = (@'
set -e
mkdir -p /work
cd /src
tar --exclude=obj --exclude=TestResults --exclude=.git -cf - . | tar -xf - -C /work
cd /work/tests/EkmMock.Server.Tests/bin/$CONFIGURATION/net10.0
mkdir -p "$STUB_ROOT"
cp /work/src/EkmMock.Server/appsettings.json "$STUB_ROOT/"
dotnet --list-runtimes
dotnet EkmMock.Server.Tests.dll $TEST_ARGS
'@) -replace "`r`n", "`n"

docker run --rm `
    -v "${repo}:/src:ro" `
    -e "CONFIGURATION=$Configuration" `
    -e "STUB_ROOT=$stubRoot" `
    -e "TEST_ARGS=$TestArgs" `
    $Image bash -c $inner

exit $LASTEXITCODE
