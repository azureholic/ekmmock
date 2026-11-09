<#
.SYNOPSIS
    EkmMock developer targets for Windows (the PowerShell twin of the Makefile, spec 11.2).

.DESCRIPTION
    Targets (same names as `make`):
      dev               generate a test PKI, init a data folder, start the server with --dev in this window (sample keys aes-key-1 / rsa-key-1, fake Managed HSM client trusted)
      conformance-host  the conformance suite from the host CLI against a running `dev`
      build             dotnet build -warnaserror
      test              dotnet test
      image             docker build -f deploy/docker/Dockerfile -t ekmmock:local .
      compose-up        docker compose -f deploy/docker/compose.dev.yaml up -d --build, then waits for the seeding container and a healthy server
      conformance       the conformance suite inside the compose dev container (report: .\out\conformance-report.json)
      compose-down      stop the compose dev stack and delete its volume
      clean             remove build output and .\out

    Environment: EKMMOCK_EKM_PORT / EKMMOCK_CONSOLE_PORT (host ports; compose default 443 / 8080, `dev` default 8443 / 8080), NUGET_SOURCE (restore source for the image build
    on a network that cannot reach nuget.org, see docs/DECISIONS.md "M9: Docker build and restore").

.EXAMPLE
    scripts\dev.ps1 dev
.EXAMPLE
    scripts\dev.ps1 compose-up; scripts\dev.ps1 conformance
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('help', 'dev', 'conformance-host', 'build', 'test', 'image', 'compose-up', 'conformance', 'compose-down', 'clean')]
    [string]$Target = 'help'
)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $repo

$compose = @('compose', '-f', 'deploy/docker/compose.dev.yaml')
$out = Join-Path $repo 'out'
$dev = Join-Path $out 'dev'
$cliDll = Join-Path $repo 'src/EkmMock.Cli/bin/Debug/net10.0/ekmmock.dll'
$ekmPort = if ($env:EKMMOCK_EKM_PORT) { $env:EKMMOCK_EKM_PORT } else { '8443' }
$consolePort = if ($env:EKMMOCK_CONSOLE_PORT) { $env:EKMMOCK_CONSOLE_PORT } else { '8080' }

function Invoke-Native {
    param([string]$File, [string[]]$Arguments)
    & $File @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$File $($Arguments -join ' ') failed with exit code $LASTEXITCODE" }
}

function Invoke-Cli {
    param([string[]]$Arguments)
    Invoke-Native 'dotnet' (@($cliDll) + $Arguments)
}

function Get-ConformanceArguments {
    param([string]$Pki, [string]$Url, [string]$ConsoleUrl, [string]$Report)
    @(
        'test', 'conformance',
        '--url', $Url,
        '--client-cert', "$Pki/client.crt", '--client-key', "$Pki/client.key", '--ca', "$Pki/root-ca.pem",
        '--alt-client-cert', "$Pki/client-wrong-cn.crt", '--alt-client-key', "$Pki/client-wrong-cn.key",
        '--rogue-client-cert', "$Pki/client-untrusted-ca.crt", '--rogue-client-key', "$Pki/client-untrusted-ca.key",
        '--replacement-server-cert', "$Pki/server-replacement.crt", '--replacement-server-key', "$Pki/server-replacement.key",
        '--console', $ConsoleUrl, '--console-ca', "$Pki/root-ca.pem",
        '--allow-disruptive', '--report', $Report)
}

switch ($Target) {
    'help' { Get-Help $PSCommandPath -Detailed }

    'build' { Invoke-Native 'dotnet' @('build', 'EkmMock.sln', '-warnaserror') }

    'test' { Invoke-Native 'dotnet' @('test', 'EkmMock.sln') }

    'image' {
        Invoke-Native 'docker' @('build', '-f', 'deploy/docker/Dockerfile', '-t', 'ekmmock:local', '--build-arg', "NUGET_SOURCE=$($env:NUGET_SOURCE)", '.')
    }

    'dev' {
        Invoke-Native 'dotnet' @('build', 'src/EkmMock.Cli/EkmMock.Cli.csproj', '-warnaserror')
        Invoke-Native 'dotnet' @('build', 'src/EkmMock.Server/EkmMock.Server.csproj', '-warnaserror')

        $pki = Join-Path $dev 'pki'
        $data = Join-Path $dev 'data'
        New-Item -ItemType Directory -Force (Join-Path $data 'tls') | Out-Null
        if (-not (Test-Path (Join-Path $pki 'root-ca.pem'))) { Invoke-Cli @('certs', 'dev', '--out', $pki, '--fqdn', 'localhost') }
        Invoke-Cli @('init', '--data', $data)
        # The server persists an uploaded certificate over its own files: give it copies, so the PKI folder stays what the CLI wrote.
        Copy-Item (Join-Path $pki 'server.crt') (Join-Path $data 'tls/live.crt') -Force
        Copy-Item (Join-Path $pki 'server.key') (Join-Path $data 'tls/live.key') -Force

        # Trust the fake Managed HSM client as soon as the console answers (a background process that shares this console), then run the server in the foreground.
        $consoleUrl = "https://127.0.0.1:$consolePort"
        $seedScript = @"
for (`$i = 0; `$i -lt 90; `$i++) {
    & dotnet '$cliDll' health --ready --console '$consoleUrl' --console-ca '$pki/root-ca.pem' *> `$null
    if (`$LASTEXITCODE -eq 0) {
        & dotnet '$cliDll' trust import --ns _default --json '$pki/mhsm-client.json' --console '$consoleUrl' --console-ca '$pki/root-ca.pem'
        'EkmMock is ready (sample keys aes-key-1 and rsa-key-1, fake Managed HSM client trusted). In another shell: scripts\dev.ps1 conformance-host'
        exit 0
    }
    Start-Sleep -Seconds 1
}
'the console did not come up'
"@
        $seed = Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList @('-NoProfile', '-Command', $seedScript) -NoNewWindow -PassThru
        $env:Data__Path = $data
        $env:EKMMOCK_MASTER_KEY_FILE = Join-Path $data 'master.key'
        $env:Tls__CertFile = Join-Path $data 'tls/live.crt'
        $env:Tls__KeyFile = Join-Path $data 'tls/live.key'
        $env:Endpoints__Ekm__Url = "https://0.0.0.0:$ekmPort"
        $env:Endpoints__Console__Url = $consoleUrl
        $env:Dev__SeedSampleKeys = 'true'
        $env:EKMMOCK_ALLOW_KEY_IMPORT = 'true'
        $env:EKMMOCK_ENABLE_FAULTS = 'true'
        try {
            & dotnet run --project src/EkmMock.Server --no-build -- --dev
        }
        finally {
            if ($seed -and -not $seed.HasExited) { Stop-Process -Id $seed.Id -Force -ErrorAction SilentlyContinue }
        }
    }

    'conformance-host' {
        New-Item -ItemType Directory -Force $out | Out-Null
        $pki = Join-Path $dev 'pki'
        Invoke-Cli (Get-ConformanceArguments -Pki $pki -Url "https://localhost:$ekmPort" -ConsoleUrl "https://127.0.0.1:$consolePort" -Report (Join-Path $out 'conformance-report.json'))
    }

    'compose-up' {
        # `up --wait` fails on some Compose versions because the one-shot containers exit, so wait for them explicitly: dev-seed ends only after dev-init and a healthy server.
        Invoke-Native 'docker' ($compose + @('up', '-d', '--build'))
        $code = (& docker wait ekmmock-dev-seed)
        if ($code -ne '0') {
            & docker @compose logs dev-init dev-seed
            throw "dev-seed failed (exit code $code)"
        }
        for ($i = 0; $i -lt 90; $i++) {
            if ((& docker inspect -f '{{.State.Health.Status}}' ekmmock-dev) -eq 'healthy') {
                'EkmMock is up (healthy), sample keys aes-key-1 and rsa-key-1, fake Managed HSM client trusted.'
                return
            }
            Start-Sleep -Seconds 1
        }
        & docker @compose logs ekmmock
        throw 'ekmmock did not become healthy'
    }

    'compose-down' { Invoke-Native 'docker' ($compose + @('down', '-v')) }

    'conformance' {
        New-Item -ItemType Directory -Force $out | Out-Null
        $arguments = Get-ConformanceArguments -Pki '/data/dev-pki' -Url 'https://localhost:8443' -ConsoleUrl 'https://127.0.0.1:8080' -Report '/data/reports/conformance-report.json'
        Invoke-Native 'docker' ($compose + @('exec', '-T', 'ekmmock', 'ekmmock') + $arguments)
        Invoke-Native 'docker' ($compose + @('cp', 'ekmmock:/data/reports/conformance-report.json', (Join-Path $out 'conformance-report.json')))
    }

    'clean' {
        & dotnet clean EkmMock.sln -v q
        if (Test-Path $out) { Remove-Item $out -Recurse -Force }
    }
}
