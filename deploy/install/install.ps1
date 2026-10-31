[CmdletBinding()]
param(
    [ValidateSet('local', 'server', 'worker')]
    [string]$Mode = 'local',
    [string]$DataDir = "$env:ProgramData\Red2PR",
    [string]$Manifest = "$PSScriptRoot\release-manifest.json",
    [string]$Signature = "$PSScriptRoot\release-manifest.sig",
    [switch]$DryRun,
    [switch]$VerifyOnly,
    [switch]$Resume
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$installScript = Join-Path $PSScriptRoot 'install.sh'
$securityScript = Join-Path (Split-Path $PSScriptRoot -Parent) 'security/sign_release.py'
$trustRoot = Join-Path $PSScriptRoot 'trust-root.pub'
$revokedKeys = Join-Path $PSScriptRoot 'trust-root.revoked'

function Stop-Install([string]$Message, [int]$Code = 2) {
    [Console]::Error.WriteLine("red2pr installer: $Message")
    exit $Code
}

function ConvertTo-WslPath([string]$Path) {
    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    $converted = & wsl.exe --exec wslpath --unix $resolved 2>$null
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace(($converted -join ''))) {
        Stop-Install "cannot map a verified local path into WSL: $Path"
    }
    return ($converted -join '').Trim()
}

function Save-Checkpoint([string]$Phase, [string]$ManifestDigest) {
    if ($DryRun) { return }
    try {
        $canonicalDataDir = [System.IO.Path]::GetFullPath($DataDir)
        $programDataPath = [System.IO.Path]::GetFullPath($env:ProgramData).TrimEnd('\')
        $windowsPath = [System.IO.Path]::GetFullPath($env:windir).TrimEnd('\')
        $programFilesPath = [System.IO.Path]::GetFullPath($env:ProgramFiles).TrimEnd('\')
        if (
            $canonicalDataDir.TrimEnd('\') -ieq $programDataPath -or
            $canonicalDataDir.TrimEnd('\') -ieq $windowsPath -or
            $canonicalDataDir.StartsWith("$windowsPath\", [StringComparison]::OrdinalIgnoreCase) -or
            $canonicalDataDir.TrimEnd('\') -ieq $programFilesPath -or
            $canonicalDataDir.StartsWith("$programFilesPath\", [StringComparison]::OrdinalIgnoreCase) -or
            $canonicalDataDir.TrimEnd('\') -ieq [System.IO.Path]::GetPathRoot($canonicalDataDir).TrimEnd('\')
        ) {
            Stop-Install 'data directory resolves to a protected Windows system directory'
        }
        [System.IO.Directory]::CreateDirectory($canonicalDataDir) | Out-Null
        $checkpoint = [ordered]@{
            schema_version = 1
            phase = $Phase
            mode = $Mode
            data_dir = $canonicalDataDir
            manifest_sha256 = $ManifestDigest
            recorded_at_utc = [DateTime]::UtcNow.ToString('o')
        }
        $target = Join-Path $canonicalDataDir 'install-state.json'
        if (Test-Path -LiteralPath $target) {
            $existing = Get-Content -LiteralPath $target -Raw | ConvertFrom-Json
            if (
                $existing.phase -ceq $Phase -and
                $existing.mode -ceq $Mode -and
                $existing.data_dir -ceq $canonicalDataDir -and
                $existing.manifest_sha256 -ceq $ManifestDigest
            ) { return }
            Stop-Install 'an unrelated installer checkpoint already exists; inspect it before retrying'
        }
        $temporary = "$target.$([guid]::NewGuid().ToString('N')).tmp"
        [System.IO.File]::WriteAllText($temporary, ($checkpoint | ConvertTo-Json -Compress), [System.Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $temporary -Destination $target
    }
    catch {
        Stop-Install "could not persist the non-secret reboot checkpoint: $($_.Exception.Message)"
    }
}

if (-not (Test-Path -LiteralPath $Manifest -PathType Leaf) -or -not (Test-Path -LiteralPath $Signature -PathType Leaf)) {
    Stop-Install 'signed release manifest and detached signature are required'
}
if (-not (Test-Path -LiteralPath $trustRoot -PathType Leaf)) {
    Stop-Install 'pinned offline trust root is missing'
}

$wslCommand = Get-Command wsl.exe -ErrorAction SilentlyContinue
if (-not $wslCommand) {
    $manifestHash = (Get-FileHash -LiteralPath $Manifest -Algorithm SHA256).Hash.ToLowerInvariant()
    Save-Checkpoint 'needs_restart' $manifestHash
    Stop-Install 'needs_restart: install or enable WSL2, reboot if requested, then rerun with -Resume' 3
}
$wslStatus = & wsl.exe --status 2>&1
if ($LASTEXITCODE -ne 0) {
    $manifestHash = (Get-FileHash -LiteralPath $Manifest -Algorithm SHA256).Hash.ToLowerInvariant()
    Save-Checkpoint 'needs_restart' $manifestHash
    Stop-Install 'needs_restart: WSL2 is unavailable; follow the operator instructions, reboot if requested, then rerun with -Resume' 3
}
$distributions = & wsl.exe --list --quiet 2>$null | ForEach-Object { ([string]$_).Trim([char]0, ' ', "`r", "`n") } | Where-Object { $_ }
if (-not $distributions) {
    $manifestHash = (Get-FileHash -LiteralPath $Manifest -Algorithm SHA256).Hash.ToLowerInvariant()
    Save-Checkpoint 'needs_restart' $manifestHash
    Stop-Install 'needs_restart: install an Ubuntu WSL2 distribution, then rerun with -Resume' 3
}
$distributionDetails = & wsl.exe --list --verbose 2>$null | Out-String
if ($LASTEXITCODE -ne 0 -or $distributionDetails -notmatch '(?m)\s2\s*$') {
    $manifestHash = (Get-FileHash -LiteralPath $Manifest -Algorithm SHA256).Hash.ToLowerInvariant()
    Save-Checkpoint 'needs_restart' $manifestHash
    Stop-Install 'needs_restart: configure an installed WSL2 (version 2) distribution, then rerun with -Resume' 3
}

$script:releaseDocument = Get-Content -LiteralPath $Manifest -Raw | ConvertFrom-Json

function Verify-Release {
    $manifestHash = (Get-FileHash -LiteralPath $Manifest -Algorithm SHA256).Hash.ToLowerInvariant()
    $expectedKey = (Get-FileHash -LiteralPath $trustRoot -Algorithm SHA256).Hash.ToLowerInvariant()
    if (-not $script:releaseDocument.key_id -or $script:releaseDocument.key_id -cne $expectedKey) {
        Stop-Install 'manifest key identifier does not match the pinned offline trust root'
    }
    if (Test-Path -LiteralPath $revokedKeys -PathType Leaf) {
        $revoked = Get-Content -LiteralPath $revokedKeys | Where-Object { $_ -and -not $_.TrimStart().StartsWith('#') }
        if ($revoked -contains $expectedKey) { Stop-Install 'release signing key is revoked' }
    }
    $manifestWsl = ConvertTo-WslPath $Manifest
    $signatureWsl = ConvertTo-WslPath $Signature
    $trustRootWsl = ConvertTo-WslPath $trustRoot
    $securityWsl = ConvertTo-WslPath $securityScript
    & wsl.exe --exec python3 $securityWsl validate --input $manifestWsl 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { Stop-Install 'release manifest structure validation failed' }
    & wsl.exe --exec openssl pkeyutl -verify -rawin -pubin -inkey $trustRootWsl -in $manifestWsl -sigfile $signatureWsl 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { Stop-Install 'release Ed25519 signature verification failed' }
    return $manifestHash
}

$verifiedManifestHash = Verify-Release
if ($Resume) {
    $checkpointPath = Join-Path ([System.IO.Path]::GetFullPath($DataDir)) 'install-state.json'
    if (-not (Test-Path -LiteralPath $checkpointPath -PathType Leaf)) { Stop-Install 'no installer checkpoint exists to resume' }
    $checkpoint = Get-Content -LiteralPath $checkpointPath -Raw | ConvertFrom-Json
    if ($checkpoint.phase -cne 'needs_restart' -or $checkpoint.mode -cne $Mode -or $checkpoint.manifest_sha256 -cne $verifiedManifestHash) {
        Stop-Install 'installer checkpoint does not match this signed manifest and mode'
    }
    if ([System.IO.Path]::GetFullPath($checkpoint.data_dir) -cne [System.IO.Path]::GetFullPath($DataDir)) {
        Stop-Install 'installer checkpoint data directory changed; start a new installation explicitly'
    }
}
if ($VerifyOnly) {
    Write-Output "Verified signed Red2PR release $($script:releaseDocument.version)."
    exit 0
}

$os = Get-CimInstance -ClassName Win32_OperatingSystem
$computer = Get-CimInstance -ClassName Win32_ComputerSystem
$minimum = $script:releaseDocument.minimums.windows
if ([int]$os.BuildNumber -lt [int]$minimum.build) { Stop-Install "Windows build $($minimum.build) or newer is required" }
if ([string]$computer.SystemType -notmatch 'x64-based') { Stop-Install 'this release requires x86_64 Windows' }
if ([int]$computer.NumberOfLogicalProcessors -lt [int]$minimum.cpus) { Stop-Install "host requires at least $($minimum.cpus) CPUs" }
if ([long]$computer.TotalPhysicalMemory -lt [long]$minimum.ram_bytes) { Stop-Install "host requires at least $($minimum.ram_bytes) bytes of memory" }
$drive = [System.IO.Path]::GetPathRoot([System.IO.Path]::GetFullPath($DataDir))
$disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$($drive.TrimEnd('\'))'"
if ([long]$disk.FreeSpace -lt [long]$minimum.disk_bytes) { Stop-Install "data volume requires at least $($minimum.disk_bytes) free bytes" }

$scriptWsl = ConvertTo-WslPath $installScript
$manifestWsl = ConvertTo-WslPath $Manifest
$signatureWsl = ConvertTo-WslPath $Signature
$dataDirWsl = (& wsl.exe --exec wslpath --unix ([System.IO.Path]::GetFullPath($DataDir)) 2>$null | ForEach-Object { ([string]$_).Trim() }) -join ''
if ($LASTEXITCODE -ne 0 -or -not $dataDirWsl) { Stop-Install 'cannot map the data directory into WSL' }
$arguments = @('--exec', 'bash', $scriptWsl, '--mode', $Mode, '--data-dir', $dataDirWsl, '--manifest', $manifestWsl, '--signature', $signatureWsl)
if ($DryRun) { $arguments += '--dry-run' }
# The offline signature and Windows prerequisites were checked before launching Bash.
& wsl.exe @arguments
$exitCode = $LASTEXITCODE
if ($exitCode -ne 0) { Stop-Install "WSL installer failed with exit code $exitCode" $exitCode }
if ($Resume) {
    $checkpointPath = Join-Path ([System.IO.Path]::GetFullPath($DataDir)) 'install-state.json'
    if (Test-Path -LiteralPath $checkpointPath -PathType Leaf) { Remove-Item -LiteralPath $checkpointPath -Force }
}
exit 0
