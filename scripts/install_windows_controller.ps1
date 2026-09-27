param(
    [Parameter(Mandatory = $true)]
    [string]$ControllerExecutable,
    [Parameter(Mandatory = $true)]
    [string]$DaemonExecutable,
    [Parameter(Mandatory = $true)]
    [string]$PairingExecutable,
    [Parameter(Mandatory = $true)]
    [string]$CliExecutable,
    # Omit to install the programs only; the app then authorizes this computer.
    [string]$InstallationDirectory,
    [string[]]$LanInterface = @(),
    [ValidateSet('Plan', 'Apply', 'Verify')]
    [string]$Mode = 'Plan'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$taskName = 'Keyferry Desktop'
$legacyTaskName = 'Keyferry Gateway'
$programRoot = Join-Path $env:LOCALAPPDATA 'Programs\Keyferry'
$stateRoot = Join-Path $env:LOCALAPPDATA 'keyferry'
$installedController = Join-Path $programRoot 'keyferry.exe'
$installedDaemon = Join-Path $programRoot 'keyferryd.exe'
$installedPairing = Join-Path $programRoot 'keyferry-pairing.exe'
$installedCli = Join-Path $programRoot 'keyctl.exe'
$installedInstallation = Join-Path $stateRoot 'installation'
$shortcutPath = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Keyferry.lnk'
$currentAccount = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$selectedLanInterfaces = [Collections.Generic.List[string]]::new()
$seenLanInterfaces = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($name in @($LanInterface)) {
    if ([string]::IsNullOrWhiteSpace($name) -or
        $name -notmatch '^[\p{L}\p{N}][\p{L}\p{N} ._()-]{0,127}$' -or
        -not $seenLanInterfaces.Add($name)) {
        throw 'Each LAN interface name must be nonempty, unique, and contain only letters, numbers, spaces, dots, underscores, parentheses, or hyphens.'
    }
    $selectedLanInterfaces.Add($name)
}
$lanArguments = @($selectedLanInterfaces | ForEach-Object { "--lan-interface `"$_`"" }) -join ' '
$expectedArguments = "--installation `"$installedInstallation`""
if ($lanArguments.Length -gt 0) {
    $expectedArguments += " $lanArguments"
}

function Get-AccountSid {
    param([string]$Account)

    try {
        $identity = [Security.Principal.NTAccount]::new($Account)
        return $identity.Translate([Security.Principal.SecurityIdentifier]).Value
    } catch {
        return $null
    }
}

function Test-PrivateIPv4 {
    param([Net.IPAddress]$Address)

    $bytes = $Address.GetAddressBytes()
    return $bytes.Length -eq 4 -and (
        $bytes[0] -eq 10 -or
        ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or
        ($bytes[0] -eq 192 -and $bytes[1] -eq 168)
    )
}

function Get-RequiredFile {
    param([string]$Path, [string]$Label)

    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw "$Label is missing."
    }
    return $resolved
}

function Get-TreeHash {
    param([string]$Root)

    $resolved = (Resolve-Path -LiteralPath $Root -ErrorAction Stop).Path.TrimEnd('\')
    if (-not (Test-Path -LiteralPath $resolved -PathType Container)) {
        throw 'Installation credentials are missing.'
    }
    $files = @(Get-ChildItem -LiteralPath $resolved -Recurse -Force -File | Sort-Object FullName)
    if ($files.Count -eq 0 -or $files.Count -gt 64) {
        throw 'Installation credential file count is invalid.'
    }
    if (Get-ChildItem -LiteralPath $resolved -Recurse -Force | Where-Object {
        ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
    }) {
        throw 'Installation credentials must not contain links or reparse points.'
    }
    $total = ($files | Measure-Object -Property Length -Sum).Sum
    if ($total -gt 262144) {
        throw 'Installation credentials exceed their bounded size.'
    }
    $records = $files | ForEach-Object {
        $relative = $_.FullName.Substring($resolved.Length).TrimStart('\')
        "$relative`t$((Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash)"
    }
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes(($records -join "`n"))
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '')
    } finally {
        $sha.Dispose()
    }
}

function Stop-InstalledProcess {
    param([string]$Name, [string]$ExactPath)

    $processes = @(Get-Process $Name -ErrorAction SilentlyContinue | Where-Object {
        try { $_.Path -eq $ExactPath } catch { $false }
    })
    if ($processes.Count -eq 0) { return }
    $processes | Stop-Process -Force
    $processes | Wait-Process -Timeout 10 -ErrorAction Stop
}

function Test-InstalledDaemonProcess {
    param([object]$process)

    if ($null -eq $process -or
        $process.ExecutablePath -ine $installedDaemon -or
        [string]::IsNullOrWhiteSpace($process.CommandLine)) {
        return $false
    }
    return $process.CommandLine.Contains($expectedArguments)
}

function Get-InstalledDaemonProcessId {
    $listeners = @(Get-NetTCPConnection -State Listen -LocalAddress 127.0.0.1 `
        -LocalPort 8042 -ErrorAction SilentlyContinue)
    foreach ($listener in $listeners) {
        $process = Get-CimInstance Win32_Process `
            -Filter "ProcessId=$($listener.OwningProcess)" -ErrorAction SilentlyContinue
        if (Test-InstalledDaemonProcess $process) {
            return [int]$listener.OwningProcess
        }
    }
    return $null
}

# An unauthorized daemon waits for credentials without listeners, so only its command identifies it.
function Get-InstalledDaemonCommandProcessId {
    $processes = @(Get-CimInstance Win32_Process -Filter "Name='keyferryd.exe'" `
        -ErrorAction SilentlyContinue)
    foreach ($process in $processes) {
        if (Test-InstalledDaemonProcess $process) {
            return [int]$process.ProcessId
        }
    }
    return $null
}

function Test-KnownLegacyTask {
    param([object]$Task)

    $actions = @($Task.Actions)
    if ($actions.Count -ne 1 -or
        $actions[0].Execute -ine $installedDaemon -or
        $actions[0].WorkingDirectory -ine $programRoot -or
        (Get-AccountSid $Task.Principal.UserId) -ne $currentSid -or
        $Task.Principal.LogonType -ne 'Interactive' -or
        $Task.Principal.RunLevel -ne 'Limited') {
        return $false
    }
    $legacyConfig = Join-Path $stateRoot 'gateway\runtime.json'
    $pattern = '^--config "' + [Regex]::Escape($legacyConfig) +
        '" --ble --tailnet-address 100\.(?:[0-9]{1,3}\.){2}[0-9]{1,3} --tailnet-port 18043$'
    return $actions[0].Arguments -match $pattern
}

function Restore-InstalledFile {
    param(
        [string]$Backup,
        [string]$Destination,
        [bool]$Existed
    )

    if ($Existed) {
        Copy-Item -LiteralPath $Backup -Destination $Destination -Force
    } elseif (Test-Path -LiteralPath $Destination) {
        Remove-Item -LiteralPath $Destination -Force
    }
}

function Protect-OwnerOnly {
    param([string]$Path)

    & icacls.exe $Path /inheritance:r /grant:r "${currentAccount}:(OI)(CI)F" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Could not protect $Path for the current user."
    }
}

function Restore-AccessRules {
    param(
        [string]$Path,
        [string]$AccessSddl
    )

    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetSecurityDescriptorSddlForm(
        $AccessSddl,
        [Security.AccessControl.AccessControlSections]::Access
    )
    $directory = [IO.DirectoryInfo]::new($Path)
    [IO.FileSystemAclExtensions]::SetAccessControl($directory, $security)
}

function Install-FileWithRollback {
    param([string]$Staged, [string]$Destination)

    $previous = "$Destination.previous"
    if (Test-Path -LiteralPath $previous) {
        Remove-Item -LiteralPath $previous -Force
    }
    if (Test-Path -LiteralPath $Destination) {
        Move-Item -LiteralPath $Destination -Destination $previous
    }
    try {
        Move-Item -LiteralPath $Staged -Destination $Destination
    } catch {
        if ((-not (Test-Path -LiteralPath $Destination)) -and
            (Test-Path -LiteralPath $previous)) {
            Move-Item -LiteralPath $previous -Destination $Destination
        }
        throw
    }
}

function Install-DirectoryWithRollback {
    param([string]$Staged, [string]$Destination)

    $previous = "$Destination.previous"
    if (Test-Path -LiteralPath $previous) {
        if (Test-Path -LiteralPath $Destination) {
            Remove-Item -LiteralPath $previous -Recurse -Force
        } else {
            Move-Item -LiteralPath $previous -Destination $Destination
        }
    }
    if (Test-Path -LiteralPath $Destination) {
        Move-Item -LiteralPath $Destination -Destination $previous
    }
    try {
        Move-Item -LiteralPath $Staged -Destination $Destination
    } catch {
        if ((-not (Test-Path -LiteralPath $Destination)) -and
            (Test-Path -LiteralPath $previous)) {
            Move-Item -LiteralPath $previous -Destination $Destination
        }
        throw
    }
    if (Test-Path -LiteralPath $previous) {
        Remove-Item -LiteralPath $previous -Recurse -Force
    }
}

$sourceController = Get-RequiredFile $ControllerExecutable 'Controller executable'
$sourceDaemon = Get-RequiredFile $DaemonExecutable 'Daemon executable'
$sourcePairing = Get-RequiredFile $PairingExecutable 'Pairing helper'
$sourceCli = Get-RequiredFile $CliExecutable 'Agent CLI'
$programOnly = [string]::IsNullOrWhiteSpace($InstallationDirectory)
$sourceInstallation = $null
$sourceInstallationHash = if (Test-Path -LiteralPath $installedInstallation -PathType Container) {
    'existing credentials unchanged'
} else {
    'authorize this computer in the Keyferry app'
}
if (-not $programOnly) {
    $sourceInstallation = (Resolve-Path -LiteralPath $InstallationDirectory -ErrorAction Stop).Path.TrimEnd('\')
    $sourceInstallationHash = Get-TreeHash $sourceInstallation
    & $sourcePairing validate-installation --input $sourceInstallation | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'Installation credential validation failed.'
    }
}

$controllerHash = (Get-FileHash -LiteralPath $sourceController -Algorithm SHA256).Hash
$daemonHash = (Get-FileHash -LiteralPath $sourceDaemon -Algorithm SHA256).Hash
$pairingHash = (Get-FileHash -LiteralPath $sourcePairing -Algorithm SHA256).Hash
$cliHash = (Get-FileHash -LiteralPath $sourceCli -Algorithm SHA256).Hash
$detectedLegacyTask = Get-ScheduledTask -TaskName $legacyTaskName -ErrorAction SilentlyContinue
if ($null -ne $detectedLegacyTask -and -not (Test-KnownLegacyTask $detectedLegacyTask)) {
    throw "A task named '$legacyTaskName' exists but is not the recognized legacy Keyferry gateway."
}

if ($Mode -eq 'Plan') {
    [pscustomobject]@{
        Role = 'desktop-and-nearby-gateway'
        Account = $currentAccount
        Controller = $installedController
        ControllerSHA256 = $controllerHash
        Daemon = $installedDaemon
        DaemonSHA256 = $daemonHash
        PairingHelper = $installedPairing
        PairingHelperSHA256 = $pairingHash
        AgentCLI = $installedCli
        AgentCLISHA256 = $cliHash
        Installation = $installedInstallation
        InstallationTreeSHA256 = $sourceInstallationHash
        DaemonArguments = $expectedArguments
        DaemonRuns = 'only while the Keyferry app is open'
        LanInterfaces = @($selectedLanInterfaces)
        LegacyGatewayRetirement = if ($null -ne $detectedLegacyTask) {
            'after successful Apply'
        } else {
            'not present'
        }
    }
    exit 0
}

$legacyTask = $detectedLegacyTask
$restoreLegacyTask = $false
$applyStarted = $false
$applySucceeded = $false
$rollbackRoot = $null
$desktopTaskBefore = $null
$desktopTaskXml = $null
$desktopTaskWasRunning = $false
$verificationStartedDaemon = $false
$hadController = $false
$hadDaemon = $false
$hadPairing = $false
$hadCli = $false
$hadInstallation = $false
$hadShortcut = $false
$programAccessSddlBefore = $null
$stateAccessSddlBefore = $null
try {
if ($Mode -eq 'Apply') {
    if (-not $programOnly -and (Test-Path -LiteralPath $installedInstallation) -and
        (Get-TreeHash $installedInstallation) -cne $sourceInstallationHash) {
        & $sourcePairing validate-installation-upgrade `
            --existing $installedInstallation --candidate $sourceInstallation | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw 'Installation credential expansion validation failed.'
        }
    }

    $desktopTaskBefore = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($null -ne $desktopTaskBefore) {
        $desktopTaskXml = Export-ScheduledTask -TaskName $taskName
        $desktopTaskWasRunning = $desktopTaskBefore.State -eq 'Running'
    }
    $hadController = Test-Path -LiteralPath $installedController -PathType Leaf
    $hadDaemon = Test-Path -LiteralPath $installedDaemon -PathType Leaf
    $hadPairing = Test-Path -LiteralPath $installedPairing -PathType Leaf
    $hadCli = Test-Path -LiteralPath $installedCli -PathType Leaf
    $hadInstallation = Test-Path -LiteralPath $installedInstallation -PathType Container
    $hadShortcut = Test-Path -LiteralPath $shortcutPath -PathType Leaf
    if (Test-Path -LiteralPath $programRoot) {
        $programAccessSddlBefore = (Get-Acl -LiteralPath $programRoot).GetSecurityDescriptorSddlForm(
            [Security.AccessControl.AccessControlSections]::Access
        )
    }
    if (Test-Path -LiteralPath $stateRoot) {
        $stateAccessSddlBefore = (Get-Acl -LiteralPath $stateRoot).GetSecurityDescriptorSddlForm(
            [Security.AccessControl.AccessControlSections]::Access
        )
    }
    $rollbackRoot = Join-Path ([IO.Path]::GetTempPath()) `
        ('.keyferry-desktop-rollback-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $rollbackRoot | Out-Null
    if ($hadController) { Copy-Item -LiteralPath $installedController -Destination (Join-Path $rollbackRoot 'keyferry.exe') }
    if ($hadDaemon) { Copy-Item -LiteralPath $installedDaemon -Destination (Join-Path $rollbackRoot 'keyferryd.exe') }
    if ($hadPairing) { Copy-Item -LiteralPath $installedPairing -Destination (Join-Path $rollbackRoot 'keyferry-pairing.exe') }
    if ($hadCli) { Copy-Item -LiteralPath $installedCli -Destination (Join-Path $rollbackRoot 'keyctl.exe') }
    if ($hadInstallation) { Copy-Item -LiteralPath $installedInstallation -Destination (Join-Path $rollbackRoot 'installation') -Recurse }
    if ($hadShortcut) { Copy-Item -LiteralPath $shortcutPath -Destination (Join-Path $rollbackRoot 'Keyferry.lnk') }
    $applyStarted = $true

    if ($null -ne $legacyTask) {
        $restoreLegacyTask = $legacyTask.State -eq 'Running'
        Stop-ScheduledTask -TaskName $legacyTaskName -ErrorAction SilentlyContinue
    }

    if ($null -ne $desktopTaskBefore) {
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    }
    Stop-InstalledProcess -Name 'keyferry' -ExactPath $installedController
    Stop-InstalledProcess -Name 'keyferryd' -ExactPath $installedDaemon

    New-Item -ItemType Directory -Force -Path $programRoot, $stateRoot | Out-Null
    $stageRoot = Join-Path $programRoot ('.desktop-install-' + [Guid]::NewGuid().ToString('N'))
    if ((Split-Path -Parent $stageRoot) -cne $programRoot) {
        throw 'Desktop staging path escaped the program directory.'
    }
    New-Item -ItemType Directory -Path $stageRoot | Out-Null
    try {
        $stagedController = Join-Path $stageRoot 'keyferry.exe'
        $stagedDaemon = Join-Path $stageRoot 'keyferryd.exe'
        $stagedPairing = Join-Path $stageRoot 'keyferry-pairing.exe'
        $stagedCli = Join-Path $stageRoot 'keyctl.exe'
        $stagedInstallation = Join-Path $stageRoot 'installation'
        Copy-Item -LiteralPath $sourceController -Destination $stagedController
        Copy-Item -LiteralPath $sourceDaemon -Destination $stagedDaemon
        Copy-Item -LiteralPath $sourcePairing -Destination $stagedPairing
        Copy-Item -LiteralPath $sourceCli -Destination $stagedCli
        if (-not $programOnly) {
            Copy-Item -LiteralPath $sourceInstallation -Destination $stagedInstallation -Recurse
        }
        if ((Get-FileHash -LiteralPath $stagedController -Algorithm SHA256).Hash -cne $controllerHash -or
            (Get-FileHash -LiteralPath $stagedDaemon -Algorithm SHA256).Hash -cne $daemonHash -or
            (Get-FileHash -LiteralPath $stagedPairing -Algorithm SHA256).Hash -cne $pairingHash -or
            (Get-FileHash -LiteralPath $stagedCli -Algorithm SHA256).Hash -cne $cliHash) {
            throw 'Staged desktop files do not match their source hashes.'
        }
        if (-not $programOnly) {
            if ((Get-TreeHash $stagedInstallation) -cne $sourceInstallationHash) {
                throw 'Staged installation credentials do not match their source hash.'
            }
            Install-DirectoryWithRollback $stagedInstallation $installedInstallation
        }
        Install-FileWithRollback $stagedController $installedController
        Install-FileWithRollback $stagedDaemon $installedDaemon
        Install-FileWithRollback $stagedPairing $installedPairing
        Install-FileWithRollback $stagedCli $installedCli
    } finally {
        if (Test-Path -LiteralPath $stageRoot) {
            if ((Split-Path -Parent (Resolve-Path -LiteralPath $stageRoot).Path) -cne $programRoot) {
                throw 'Refusing to remove an unexpected staging directory.'
            }
            Remove-Item -LiteralPath $stageRoot -Recurse -Force
        }
    }

    Protect-OwnerOnly $programRoot
    Protect-OwnerOnly $stateRoot

    # The task defines the daemon's verified command but never starts on its own: the Keyferry app
    # runs it on launch and ends it on exit. IgnoreNew keeps a second run from starting a duplicate.
    $action = New-ScheduledTaskAction -Execute $installedDaemon -Argument $expectedArguments -WorkingDirectory $programRoot
    $principal = New-ScheduledTaskPrincipal -UserId $currentAccount -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $taskName -Action $action `
        -Principal $principal -Settings $settings `
        -Description 'Keyferry desktop daemon, run only while the Keyferry app is open: local control, nearby gateway, and authenticated tailnet route' `
        -Force | Out-Null

    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = $installedController
    $shortcut.WorkingDirectory = $programRoot
    $shortcut.IconLocation = "$installedController,0"
    $shortcut.Save()
}

$task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
$action = @($task.Actions)
if ($action.Count -ne 1 -or $action[0].Execute -cne $installedDaemon -or
    $action[0].Arguments -cne $expectedArguments -or
    $action[0].WorkingDirectory -cne $programRoot) {
    throw 'Scheduled daemon action does not match the desktop installation.'
}
if ((Get-AccountSid $task.Principal.UserId) -ne $currentSid -or
    $task.Principal.LogonType -ne 'Interactive' -or
    $task.Principal.RunLevel -ne 'Limited') {
    throw 'Scheduled daemon ownership does not match the desktop installation.'
}
if (@($task.Triggers | Where-Object { $null -ne $_ }).Count -ne 0 -or
    $task.Settings.RestartCount -ne 0 -or
    $task.Settings.MultipleInstances -ne 'IgnoreNew') {
    throw 'The scheduled daemon must run only when the Keyferry app starts it.'
}
if ((Get-FileHash -LiteralPath $installedController -Algorithm SHA256).Hash -cne $controllerHash -or
    (Get-FileHash -LiteralPath $installedDaemon -Algorithm SHA256).Hash -cne $daemonHash -or
    (Get-FileHash -LiteralPath $installedPairing -Algorithm SHA256).Hash -cne $pairingHash -or
    (Get-FileHash -LiteralPath $installedCli -Algorithm SHA256).Hash -cne $cliHash) {
    throw 'Installed desktop binaries do not match the requested release.'
}
if (-not $programOnly -and (Get-TreeHash $installedInstallation) -cne $sourceInstallationHash) {
    throw 'Installed identity does not match the requested installation credentials.'
}
$shortcut = (New-Object -ComObject WScript.Shell).CreateShortcut($shortcutPath)
if ($shortcut.TargetPath -cne $installedController -or $shortcut.WorkingDirectory -cne $programRoot) {
    throw 'The Keyferry shortcut does not match the desktop installation.'
}
# The daemon runs only while the Keyferry app is open. Verification starts it when it is not
# already running, checks it, and stops it again. Until the app authorizes this computer, the
# daemon waits without opening listeners, so only its command identifies it.
$authorized = Test-Path -LiteralPath $installedInstallation -PathType Container
if ($task.State -ne 'Running') {
    Start-ScheduledTask -TaskName $taskName
    $verificationStartedDaemon = $true
}
$deadline = [DateTime]::UtcNow.AddSeconds(10)
do {
    $daemonProcessId = if ($authorized) {
        Get-InstalledDaemonProcessId
    } else {
        Get-InstalledDaemonCommandProcessId
    }
    if ($null -ne $daemonProcessId -and
        (Get-ScheduledTask -TaskName $taskName).State -eq 'Running') { break }
    $daemonProcessId = $null
    Start-Sleep -Milliseconds 250
} while ([DateTime]::UtcNow -lt $deadline)
if ($null -eq $daemonProcessId) {
    if ($authorized) {
        throw 'The installed daemon did not open its loopback control listener.'
    }
    throw 'The scheduled task did not run the installed daemon with its expected arguments.'
}
if ($authorized) {
    foreach ($name in $selectedLanInterfaces) {
        $interfaceAddresses = @(Get-NetIPAddress -InterfaceAlias $name -AddressFamily IPv4 `
            -AddressState Preferred -ErrorAction SilentlyContinue | Where-Object {
                $_.PrefixLength -ge 1 -and $_.PrefixLength -le 30 -and
                (Test-PrivateIPv4 ([Net.IPAddress]$_.IPAddress))
            })
        if ($interfaceAddresses.Count -eq 0) {
            throw "Selected LAN interface has no active private IPv4 broadcast subnet: $name"
        }
        foreach ($interfaceAddress in $interfaceAddresses) {
            $listener = Get-NetTCPConnection -State Listen -LocalAddress $interfaceAddress.IPAddress `
                -LocalPort 7443 -ErrorAction SilentlyContinue | Where-Object {
                    $_.OwningProcess -eq $daemonProcessId
                }
            if ($null -eq $listener) {
                throw "Selected LAN interface did not open its exact device listener: $name"
            }
        }
    }

    $tailscale = Get-Command tailscale.exe -ErrorAction SilentlyContinue
    if ($null -ne $tailscale) {
        $tailnetStatusJson = & $tailscale.Source status --json 2>$null
        if ($LASTEXITCODE -ne 0) {
            throw 'Tailscale status could not be verified.'
        }
        $tailnetStatus = $tailnetStatusJson | ConvertFrom-Json
        if ($tailnetStatus.BackendState -eq 'Running') {
                $tailnetAddresses = @($tailnetStatus.Self.TailscaleIPs | Where-Object { $_ -match '^100\.' })
                if ($tailnetAddresses.Count -ne 1) {
                    throw 'Tailscale is running without one unambiguous local IPv4 address.'
                }
                $tailnetAddress = $tailnetAddresses[0]
                $tailnetDeadline = [DateTime]::UtcNow.AddSeconds(10)
                do {
                    $tailnetListeners = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object {
                        $_.OwningProcess -eq $daemonProcessId -and
                        $_.LocalAddress -eq $tailnetAddress -and
                        ($_.LocalPort -eq 18043 -or $_.LocalPort -eq 18044)
                    })
                    if ($tailnetListeners.Count -eq 2) { break }
                    Start-Sleep -Milliseconds 250
                } while ([DateTime]::UtcNow -lt $tailnetDeadline)
                if ($tailnetListeners.Count -ne 2) {
                    throw 'The installed daemon did not open both owner-authenticated tailnet listeners.'
                }
        }
    }
}

if ($verificationStartedDaemon) {
    Stop-ScheduledTask -TaskName $taskName
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    while ($null -ne (Get-InstalledDaemonCommandProcessId) -and [DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 250
    }
    if ($null -ne (Get-InstalledDaemonCommandProcessId)) {
        throw 'The installed daemon did not stop after verification.'
    }
    $verificationStartedDaemon = $false
}

if ($Mode -eq 'Apply' -and $null -ne $legacyTask) {
    Unregister-ScheduledTask -TaskName $legacyTaskName -Confirm:$false
    $restoreLegacyTask = $false
}
$applySucceeded = $Mode -eq 'Apply'

Write-Output "Verification OK: Keyferry is installed for $currentAccount as a controller and nearby gateway; its service runs only while Keyferry is open."
} finally {
    if ($verificationStartedDaemon) {
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    }
    if ($applyStarted -and -not $applySucceeded) {
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        }
        Stop-InstalledProcess -Name 'keyferryd' -ExactPath $installedDaemon
        Stop-InstalledProcess -Name 'keyferry' -ExactPath $installedController
        Restore-InstalledFile (Join-Path $rollbackRoot 'keyferry.exe') $installedController $hadController
        Restore-InstalledFile (Join-Path $rollbackRoot 'keyferryd.exe') $installedDaemon $hadDaemon
        Restore-InstalledFile (Join-Path $rollbackRoot 'keyferry-pairing.exe') $installedPairing $hadPairing
        Restore-InstalledFile (Join-Path $rollbackRoot 'keyctl.exe') $installedCli $hadCli
        Restore-InstalledFile (Join-Path $rollbackRoot 'Keyferry.lnk') $shortcutPath $hadShortcut
        if (Test-Path -LiteralPath $installedInstallation) {
            $resolvedInstallation = (Resolve-Path -LiteralPath $installedInstallation).Path
            if ($resolvedInstallation -ine $installedInstallation -or
                (Split-Path -Parent $resolvedInstallation) -ine $stateRoot) {
                throw 'Refusing to remove an unexpected installation-identity directory.'
            }
            Remove-Item -LiteralPath $resolvedInstallation -Recurse -Force
        }
        if ($hadInstallation) {
            Copy-Item -LiteralPath (Join-Path $rollbackRoot 'installation') `
                -Destination $installedInstallation -Recurse
        }
        if ($null -ne $desktopTaskBefore) {
            Register-ScheduledTask -TaskName $taskName -Xml $desktopTaskXml -Force | Out-Null
            if ($desktopTaskWasRunning) {
                Start-ScheduledTask -TaskName $taskName
            }
        }
        if ($restoreLegacyTask) {
            Start-ScheduledTask -TaskName $legacyTaskName -ErrorAction SilentlyContinue
        }
        if ($null -ne $programAccessSddlBefore -and (Test-Path -LiteralPath $programRoot)) {
            Restore-AccessRules $programRoot $programAccessSddlBefore
        }
        if ($null -ne $stateAccessSddlBefore -and (Test-Path -LiteralPath $stateRoot)) {
            Restore-AccessRules $stateRoot $stateAccessSddlBefore
        }
    }
    if ($null -ne $rollbackRoot -and (Test-Path -LiteralPath $rollbackRoot)) {
        $resolvedRollback = (Resolve-Path -LiteralPath $rollbackRoot).Path
        if ((Split-Path -Parent $resolvedRollback) -ine ([IO.Path]::GetTempPath()).TrimEnd('\')) {
            throw 'Refusing to remove an unexpected installer rollback directory.'
        }
        Remove-Item -LiteralPath $resolvedRollback -Recurse -Force
    }
}
