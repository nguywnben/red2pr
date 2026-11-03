[CmdletBinding()]
param(
    [switch]$CheckOnly,
    [switch]$SmokeTest,
    [int]$Port = 4280,
    [string]$DataDir = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path

function Stop-Quickstart([string]$Message) {
    [Console]::Error.WriteLine("red2pr quickstart: $Message")
    exit 2
}

Push-Location $repoRoot
try {
    $nodeCmd = Get-Command node -ErrorAction SilentlyContinue
    if (-not $nodeCmd) {
        Stop-Quickstart "Node.js >= 22.12 is required. Install Node.js 22 LTS and rerun .\scripts\quickstart.ps1."
    }
    $pnpmCmd = Get-Command pnpm -ErrorAction SilentlyContinue
    if (-not $pnpmCmd) {
        Stop-Quickstart "pnpm is required (corepack enable && corepack prepare pnpm@9.15.9 --activate)."
    }

    $venvPython = Join-Path $repoRoot '.venv\Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $venvPython -PathType Leaf)) {
        $uvCmd = Get-Command uv -ErrorAction SilentlyContinue
        if (-not $uvCmd) {
            Stop-Quickstart "Virtual environment .venv not found and 'uv' is not installed. Install uv (https://docs.astral.sh/uv/) and rerun."
        }
        Write-Host "Provisioning Python 3.12 virtual environment via uv sync..."
        & uv sync
        if ($LASTEXITCODE -ne 0) { Stop-Quickstart "uv sync failed." }
    }

    if (-not (Test-Path -LiteralPath (Join-Path $repoRoot 'node_modules') -PathType Container)) {
        Write-Host "Installing frontend workspace dependencies via pnpm..."
        & pnpm install --frozen-lockfile
        if ($LASTEXITCODE -ne 0) { Stop-Quickstart "pnpm install failed." }
    }

    $webIndex = Join-Path $repoRoot 'apps\web\dist\index.html'
    if ((-not $CheckOnly) -and (-not (Test-Path -LiteralPath $webIndex -PathType Leaf))) {
        Write-Host "Building Red2PR TypeScript client and React/Astryx web bundle..."
        & pnpm run quickstart:web
        if ($LASTEXITCODE -ne 0) { Stop-Quickstart "Frontend build failed." }
    }

    $pyPaths = @(
        (Join-Path $repoRoot 'packages\py-contracts\src'),
        (Join-Path $repoRoot 'apps\control-plane\src'),
        (Join-Path $repoRoot 'apps\worker-supervisor\src'),
        (Join-Path $repoRoot 'apps\cli\src')
    )
    $venvWebsockets = Join-Path $repoRoot '.venv\Lib\site-packages\websockets\__init__.py'
    if (-not (Test-Path -LiteralPath $venvWebsockets -PathType Leaf)) {
        $uvCmd = Get-Command uv -ErrorAction SilentlyContinue
        if ($uvCmd) {
            & uv sync --frozen 2>$null
        }
        if (-not (Test-Path -LiteralPath $venvWebsockets -PathType Leaf)) {
            $candidateRoots = @($env:LOCALAPPDATA, (Join-Path $env:USERPROFILE 'AppData\Local')) | Where-Object { $_ }
            foreach ($root in $candidateRoots) {
                $uvArchive = Join-Path $root 'uv\cache\archive-v0'
                if (Test-Path -LiteralPath $uvArchive -PathType Container) {
                    $wsCache = Get-ChildItem -LiteralPath $uvArchive -Directory -ErrorAction SilentlyContinue |
                        Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'websockets\__init__.py') } |
                        Select-Object -First 1
                    if ($wsCache) {
                        $pyPaths += $wsCache.FullName
                        break
                    }
                }
            }
        }
    }
    if ($env:RED2PR_EXTRA_PYTHONPATH) {
        $pyPaths += $env:RED2PR_EXTRA_PYTHONPATH
    }
    $env:PYTHONPATH = ($pyPaths -join ';')

    $mode = 'up'
    if ($CheckOnly) { $mode = 'check' }
    elseif ($SmokeTest) { $mode = 'smoke-test' }

    $stackArgs = @((Join-Path $PSScriptRoot 'dev_stack.py'), $mode, '--port', "$Port")
    if ($DataDir) {
        $stackArgs += @('--data-dir', $DataDir)
    }
    & $venvPython @stackArgs
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}
