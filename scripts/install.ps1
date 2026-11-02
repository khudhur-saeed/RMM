# -----------------------------------------------------------------------------
# Tactical RMM Windows Automated Deployment Bootstrap (install.ps1)
# -----------------------------------------------------------------------------
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage = "Control plane base URL")]
    [ValidateNotNullOrEmpty()]
    [string]$ServerUrl,

    [Parameter(Mandatory = $true, HelpMessage = "One-time enrollment bootstrap token")]
    [ValidateNotNullOrEmpty()]
    [string]$Token,

    [Parameter(Mandatory = $false, HelpMessage = "Optional local path to Root CA certificate")]
    [string]$CaCertPath = "",

    [Parameter(Mandatory = $false, HelpMessage = "Optional explicit local path to pre-compiled agent binary")]
    [string]$LocalBinaryPath = "",

    [Parameter(Mandatory = $false, HelpMessage = "Target destination installation path")]
    [string]$InstallDir = "C:\Program Files\rmmagent"
)

# Enforce strict error handling
$ErrorActionPreference = "Stop"

function Write-LogInfo {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

function Write-LogSuccess {
    param([string]$Message)
    Write-Host "[+] $Message" -ForegroundColor Green
}

function Write-LogError {
    param([string]$Message)
    Write-Host "[-] ERROR: $Message" -ForegroundColor Red
}

function Test-IsAdministrator {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-Prerequisites {
    Write-LogInfo "Validating installation prerequisites and privileges..."

    if (-not (Test-IsAdministrator)) {
        Write-LogError "Elevation required: install.ps1 must be executed in an elevated Administrator session."
        exit 1
    }

    # Normalize Server URL trailing slash
    $script:ServerUrl = $ServerUrl.TrimEnd('/')

    # Enforce TLS 1.2 and TLS 1.3
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

    # Reject non-loopback plaintext HTTP
    if ($ServerUrl -match '^http://' -and $ServerUrl -notmatch '^http://(127\.0\.0\.1|localhost)(:[0-9]+)?$') {
        Write-LogError "Insecure transport rejected: Server URL must use HTTPS outside localhost."
        exit 1
    }

    Write-LogSuccess "Execution environment verified (Administrator & Modern TLS enforced)."
}

function Stop-ExistingService {
    param([string]$ServiceName = "rmmagent")

    $existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existingService) {
        Write-LogInfo "Existing service '$ServiceName' detected. Stopping and removing stale registration..."
        
        if ($existingService.Status -eq [ServiceProcess.ServiceControllerStatus]::Running) {
            Stop-Service -Name $ServiceName -Force
            Start-Sleep -Seconds 2
        }

        # Deregister using SCM command line
        & sc.exe delete $ServiceName | Out-Null
        Start-Sleep -Seconds 1
        Write-LogSuccess "Stale service instance removed successfully."
    }
}

function Install-AgentBinary {
    $binaryTarget = Join-Path -Path $InstallDir -ChildPath "rmmagent.exe"

    if (-not (Test-Path -Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    # 1. Stage local binary only when explicitly supplied via -LocalBinaryPath
    $staged = $false
    if ($LocalBinaryPath -ne "") {
        if (-not (Test-Path -Path $LocalBinaryPath)) {
            Write-LogError "Specified LocalBinaryPath does not exist: '$LocalBinaryPath'"
            exit 1
        }
        Write-LogInfo "Staging explicitly supplied artifact from '$LocalBinaryPath'..."
        Copy-Item -Path $LocalBinaryPath -Destination $binaryTarget -Force
        $staged = $true
    }

    # 2. Network retrieval fallback
    if (-not $staged) {
        $downloadUrl = "$ServerUrl/api/v1/download/windows/amd64"
        $tmpBinary = Join-Path -Path $env:TEMP -ChildPath "rmmagent_bootstrap_$PID.exe"

        Write-LogInfo "Fetching windows agent binary from: $downloadUrl"
        try {
            $webClient = New-Object System.Net.WebClient
            $webClient.DownloadFile($downloadUrl, $tmpBinary)
            Move-Item -Path $tmpBinary -Destination $binaryTarget -Force
        } catch {
            Write-LogError "Failed to retrieve binary artifact from control plane: $_"
            if (Test-Path -Path $tmpBinary) { Remove-Item -Path $tmpBinary -Force }
            exit 1
        }
    }

    Write-LogSuccess "Binary successfully staged at: $binaryTarget"
    return $binaryTarget
}

function Register-AndStartService {
    param([string]$BinaryPath)

    Set-Location -Path $InstallDir

    # 1. Perform enrollment bootstrap
    Write-LogInfo "Initiating agent enrollment bootstrap..."
    $enrollArgs = @("-enroll-only", "-server", $ServerUrl)
    if ($CaCertPath -ne "" -and (Test-Path -Path $CaCertPath)) {
        $enrollArgs += @("-ca-cert", $CaCertPath)
    }

    $env:RMM_ENROLL_TOKEN = $Token
    try {
        $enrollProc = Start-Process -FilePath $BinaryPath -ArgumentList $enrollArgs -Wait -NoNewWindow -PassThru
    } finally {
        Remove-Item Env:\RMM_ENROLL_TOKEN -ErrorAction SilentlyContinue
    }
    if ($enrollProc.ExitCode -ne 0) {
        Write-LogError "Agent enrollment failed with exit code: $($enrollProc.ExitCode)"
        exit $enrollProc.ExitCode
    }
    Write-LogSuccess "Agent identity registered and configuration persisted."

    # 2. Register Windows Service via native agent CLI flag
    Write-LogInfo "Registering native Windows background service (SCM)..."
    $installProc = Start-Process -FilePath $BinaryPath -ArgumentList @("-service", "install") -Wait -NoNewWindow -PassThru
    if ($installProc.ExitCode -ne 0) {
        Write-LogError "Service installation failed with exit code: $($installProc.ExitCode)"
        exit $installProc.ExitCode
    }

    # 3. Launch background service via SCM
    Write-LogInfo "Starting background service..."
    $startProc = Start-Process -FilePath $BinaryPath -ArgumentList @("-service", "start") -Wait -NoNewWindow -PassThru
    if ($startProc.ExitCode -ne 0) {
        Write-LogError "Service start command failed with exit code: $($startProc.ExitCode)"
        exit $startProc.ExitCode
    }

    Start-Sleep -Seconds 2

    # 4. Final verification via SCM query
    $svc = Get-Service -Name "rmmagent" -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq [ServiceProcess.ServiceControllerStatus]::Running) {
        Write-LogSuccess "Tactical RMM Windows agent is ACTIVE and RUNNING in background (Session 0)."
    } else {
        Write-LogError "Service registration completed but status is not RUNNING."
        & sc.exe query rmmagent
        exit 1
    }
}

function Main {
    Assert-Prerequisites
    Stop-ExistingService
    $binary = Install-AgentBinary
    Register-AndStartService -BinaryPath $binary
    Write-LogSuccess "Windows endpoint unattended deployment completed successfully."
}

# Execute script entrypoint
Main