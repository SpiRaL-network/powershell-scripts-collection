#Requires -Version 4.0
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Export SMB shares, permissions, NTFS ACLs and server configuration before disk detachment.
    Run on the SOURCE server (W2K12R2) before shutdown.
    PS 4.0 compatible ; the hot paths are pure .NET and run identically (and just as fast)
    on PS 5.1+. Can also run REMOTELY from any machine via -Paths (UNC) or -ComputerName :
    in that mode only the ACLs and Inheritance steps apply.

.PARAMETER Paths
    Remote/explicit mode : scan these root paths (local or UNC, e.g. \\FILESRV\DATA)
    instead of enumerating local SMB shares. Only ACLs + Inheritance steps run.

.PARAMETER ComputerName
    Remote mode : discover the non-special SMB shares of this computer over CIM and
    scan them through UNC (\\ComputerName\ShareName). Only ACLs + Inheritance steps run.

.PARAMETER ExportRoot
    Destination folder. When omitted, a new unique folder is created automatically
    as C:\Migration_Export_YYYYMMDD_HHMMSS (with _2, _3... on collision).

.PARAMETER AllowExistingExportRoot
    Allow writing into a non-empty export folder. Disabled by default to prevent
    stale files from a previous run being included in the new manifest.

.PARAMETER DfsNamespaceServer
    DFS namespace server hostname. Leave empty to skip remote DFS export.

.PARAMETER ExcludeHiddenShares
    Skip built-in hidden shares (ADMIN$, C$, IPC$...).

.PARAMETER ExcludeDrives
    Drive letters to exclude (default: system drive C:).

.PARAMETER Interactive
    Show a step-selection menu before running. Lets you pick which steps to execute.

.PARAMETER Steps
    Comma-separated list of steps to run without the interactive menu.
    Valid values: Shares, DFS, ACLs, Inheritance, Volumes, LocalAccounts, Tasks, FSRM, LanmanReg, KVS
    Example: -Steps Shares,ACLs,KVS

.PARAMETER FullACLBackup
    ACLs step: legacy full recursive backup (icacls /save /T - folders AND files).
    Very slow on large volumes. Without this switch the ACLs step exports:
      - folder ACLs only (selected depth) as SDDL -> acls_folders_NAME.csv, one file
        per share (reapplicable via the generated Restore-FolderAcls.ps1, DACL-only)
      - a non-recursive icacls /save of each share root -> acls_root_NAME.bin

.PARAMETER AllFolderAcls
    Default folder ACL mode only writes folders that carry ACL information
    (broken inheritance or explicit ACEs) plus each share root - a folder whose
    ACL is purely inherited is fully reconstructible by propagation and carries
    no information of its own. Set this switch to write a CSV row for EVERY
    folder anyway (much larger files).

.PARAMETER FolderAclDepth
    Max depth of the folder ACL scan below each share root (default ACLs mode).
    0 = share root only, 5 = root + 5 levels of sub-folders (default),
    -1 = unlimited (full tree). Explicit ACEs deeper than this are NOT captured.

.EXAMPLE
    # Run everything (default)
    .\Export-FileServer-BeforeMigration.ps1 -DfsNamespaceServer DFSSVR01

.EXAMPLE
    # Interactive step selection
    .\Export-FileServer-BeforeMigration.ps1 -Interactive

.EXAMPLE
    # Run specific steps only
    .\Export-FileServer-BeforeMigration.ps1 -Steps Shares,ACLs,KVS

.EXAMPLE
    # Remote ACL scan from a modern admin box (PS 5.1), over UNC
    .\Export-FileServer-BeforeMigration.ps1 -Paths '\\FILESRV01\DATA','\\FILESRV01\PROJ'

.EXAMPLE
    # Remote ACL scan with automatic share discovery
    .\Export-FileServer-BeforeMigration.ps1 -ComputerName FILESRV01 -FolderAclDepth 5
#>

[CmdletBinding()]
param(
    [string]$ExportRoot = "C:\Migration_Export_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
    [switch]$AllowExistingExportRoot,
    [string]$DfsNamespaceServer = "",
    [switch]$ExcludeHiddenShares,
    [string[]]$ExcludeDrives = @($env:SystemDrive.TrimEnd('\')),
    [switch]$Interactive,
    [ValidateSet('Shares','DFS','ACLs','Inheritance','Volumes','LocalAccounts','Tasks','FSRM','LanmanReg','KVS')]
    [string[]]$Steps,

    # ACLs step: legacy full recursive icacls /save /T (folders + files, slow).
    # Default without this switch: folder-only SDDL CSV + non-recursive icacls on share roots.
    [switch]$FullACLBackup,

    # ACLs step default mode: also write CSV rows for folders whose ACL is purely
    # inherited (full dump instead of broken-inheritance/explicit-ACE folders only).
    [switch]$AllFolderAcls,

    # Max depth of the folder ACL scan (0 = share root only, -1 = unlimited)
    [ValidateRange(-1, 2147483647)]
    [int]$FolderAclDepth = 5,

    # Max folder depth for inheritance scan (0 = share root only, -1 = unlimited)
    [ValidateRange(-1, 2147483647)]
    [int]$InheritanceCheckDepth = 5,

    # Remote/explicit mode : scan these roots (local or UNC) - ACLs + Inheritance steps only
    [string[]]$Paths,

    # Remote mode : discover shares of this computer over CIM - ACLs + Inheritance steps only
    [string]$ComputerName = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# ---------------------------------------------------------------------------
# Step definitions (ordered - display order in menu)
# ---------------------------------------------------------------------------
$STEP_IDS = @('Shares','DFS','ACLs','Inheritance','Volumes','LocalAccounts','Tasks','FSRM','LanmanReg','KVS')

$aclDepthTxt = if ($FolderAclDepth -lt 0) { 'all depths' } else { "depth<=$FolderAclDepth" }

$aclStepLabel = if ($FullACLBackup) {
    'NTFS ACLs - FULL icacls /save /T (folders + files, SLOW)'
} else {
    "NTFS ACLs - folders only, $aclDepthTxt (SDDL CSV + icacls share roots)"
}

$STEP_LABELS = @{
    'Shares'      = 'SMB Shares + Share-level Permissions'
    'DFS'         = 'DFS Targets'
    'ACLs'        = $aclStepLabel
    'Inheritance' = "NTFS Inheritance map (broken inheritance, depth=$InheritanceCheckDepth)"
    'Volumes'     = 'Volumes and Disks inventory'
    'LocalAccounts' = 'Local users and local Administrators group membership'
    'Tasks'       = 'Scheduled Tasks (CSV + XML)'
    'FSRM'        = 'FSRM - CSV inventory + native XML templates and notifications'
    'LanmanReg'   = 'SMB Shares registry backup (LanmanServer\Shares)'
    'KVS'         = 'Enterprise Vault KVS registry key'
}

#region Helpers

$script:ExportWarningCount = 0
$script:ExportErrorCount   = 0
$script:FsrmNativeExportStatus = 'NotSelected'

function Write-Log {
    param([string]$Msg, [string]$Level = "INFO")
    if ($Level -eq 'WARN')  { $script:ExportWarningCount++ }
    if ($Level -eq 'ERROR') { $script:ExportErrorCount++ }
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format "HH:mm:ss"), $Level, $Msg
    $color = switch ($Level) { 'WARN' { 'Yellow' } 'ERROR' { 'Red' } default { 'Gray' } }
    Write-Host $line -ForegroundColor $color
    Add-Content -Path "$ExportRoot\summary.txt" -Value $line -Encoding UTF8
}

function Ensure-Dir {
    param([string]$Path)
    if (-not (Test-Path $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
}

function IsExcludedDrive {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $true }
    $dl = [System.IO.Path]::GetPathRoot($Path).TrimEnd('\')
    foreach ($excl in $ExcludeDrives) {
        if ($dl -ieq $excl.TrimEnd('\')) { return $true }
    }
    return $false
}

function Get-SafeName {
    param([string]$Name)
    return ($Name -replace '[^a-zA-Z0-9_\-.]', '_')
}

function ConvertTo-CsvField {
    param([string]$Value)
    return '"' + $Value.Replace('"', '""') + '"'
}

function Export-CsvBaseline {
    param(
        $Rows,
        [string]$Path,
        [string[]]$Columns
    )
    if (@($Rows).Count -gt 0) {
        $Rows | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
        return
    }

    $utf8Bom = New-Object System.Text.UTF8Encoding($true)
    $writer = New-Object System.IO.StreamWriter($Path, $false, $utf8Bom)
    try {
        $header = @($Columns | ForEach-Object { ConvertTo-CsvField $_ }) -join ','
        $writer.WriteLine($header)
    } finally {
        $writer.Dispose()
    }
}

function ConvertTo-PsSingleQuoted {
    param([string]$Value)
    return "'" + $Value.Replace("'", "''") + "'"
}

function ConvertTo-SidValue {
    param($Identity)
    if ($null -eq $Identity) { return '' }
    try {
        if ($Identity -is [System.Security.Principal.SecurityIdentifier]) {
            return $Identity.Value
        }
        $account = New-Object System.Security.Principal.NTAccount([string]$Identity)
        return $account.Translate([System.Security.Principal.SecurityIdentifier]).Value
    } catch {
        return ''
    }
}

function Get-OptionalPropertyValue {
    param($Object, [string]$Name, $DefaultValue = '')
    if ($null -eq $Object) { return $DefaultValue }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) { return $DefaultValue }
    return $property.Value
}

function Get-StorageInventory {
    $volumes = @(Get-Volume -ErrorAction Stop)
    $partitions = @(Get-Partition -ErrorAction Stop)
    $disks = @(Get-Disk -ErrorAction Stop)

    $volumeRows = foreach ($volume in $volumes) {
        $driveLetter = [string](Get-OptionalPropertyValue $volume 'DriveLetter')
        $volumeUniqueId = [string](Get-OptionalPropertyValue $volume 'UniqueId')
        $volumePath = [string](Get-OptionalPropertyValue $volume 'Path')
        $partition = $null

        if (-not [string]::IsNullOrWhiteSpace($driveLetter)) {
            $partition = $partitions | Where-Object {
                [string](Get-OptionalPropertyValue $_ 'DriveLetter') -ieq $driveLetter
            } | Select-Object -First 1
        }
        if ($null -eq $partition -and
            (-not [string]::IsNullOrWhiteSpace($volumeUniqueId) -or
             -not [string]::IsNullOrWhiteSpace($volumePath))) {
            $partition = $partitions | Where-Object {
                $accessPaths = @(Get-OptionalPropertyValue $_ 'AccessPaths' @())
                ($accessPaths -icontains $volumeUniqueId) -or ($accessPaths -icontains $volumePath)
            } | Select-Object -First 1
        }

        $disk = $null
        if ($null -ne $partition) {
            $partitionDiskNumber = Get-OptionalPropertyValue $partition 'DiskNumber' -1
            $disk = $disks | Where-Object {
                [int](Get-OptionalPropertyValue $_ 'Number' -2) -eq [int]$partitionDiskNumber
            } | Select-Object -First 1
        }

        $driveWithColon = if ([string]::IsNullOrWhiteSpace($driveLetter)) { '' } else { "$driveLetter`:" }
        $isDataDisk = (-not [string]::IsNullOrWhiteSpace($driveLetter) -and
            -not ($ExcludeDrives -contains $driveWithColon -or $ExcludeDrives -contains $driveLetter))

        [PSCustomObject]@{
            DriveLetter       = $driveLetter
            FileSystemLabel   = [string](Get-OptionalPropertyValue $volume 'FileSystemLabel')
            FileSystem        = [string](Get-OptionalPropertyValue $volume 'FileSystem')
            DriveType         = [string](Get-OptionalPropertyValue $volume 'DriveType')
            HealthStatus      = [string](Get-OptionalPropertyValue $volume 'HealthStatus')
            OperationalStatus = (@(Get-OptionalPropertyValue $volume 'OperationalStatus' @()) -join '; ')
            SizeRemaining     = [UInt64](Get-OptionalPropertyValue $volume 'SizeRemaining' 0)
            Size              = [UInt64](Get-OptionalPropertyValue $volume 'Size' 0)
            IsDataDisk        = $isDataDisk
            VolumeUniqueId    = $volumeUniqueId
            VolumePath        = $volumePath
            DiskNumber        = Get-OptionalPropertyValue $partition 'DiskNumber' ''
            PartitionNumber   = Get-OptionalPropertyValue $partition 'PartitionNumber' ''
            PartitionGuid     = [string](Get-OptionalPropertyValue $partition 'Guid')
            PartitionOffset   = Get-OptionalPropertyValue $partition 'Offset' ''
            PartitionSize     = Get-OptionalPropertyValue $partition 'Size' ''
            PartitionType     = [string](Get-OptionalPropertyValue $partition 'Type')
            DiskUniqueId      = [string](Get-OptionalPropertyValue $disk 'UniqueId')
            DiskSerialNumber  = [string](Get-OptionalPropertyValue $disk 'SerialNumber')
            DiskGuid          = [string](Get-OptionalPropertyValue $disk 'Guid')
            DiskSignature     = [string](Get-OptionalPropertyValue $disk 'Signature')
            DiskFriendlyName  = [string](Get-OptionalPropertyValue $disk 'FriendlyName')
            DiskBusType       = [string](Get-OptionalPropertyValue $disk 'BusType')
            DiskSize          = Get-OptionalPropertyValue $disk 'Size' ''
            DiskPartitionStyle= [string](Get-OptionalPropertyValue $disk 'PartitionStyle')
        }
    }

    $diskRows = foreach ($disk in $disks) {
        [PSCustomObject]@{
            Number            = Get-OptionalPropertyValue $disk 'Number' ''
            FriendlyName      = [string](Get-OptionalPropertyValue $disk 'FriendlyName')
            SerialNumber      = [string](Get-OptionalPropertyValue $disk 'SerialNumber')
            UniqueId          = [string](Get-OptionalPropertyValue $disk 'UniqueId')
            Guid              = [string](Get-OptionalPropertyValue $disk 'Guid')
            Signature         = [string](Get-OptionalPropertyValue $disk 'Signature')
            PartitionStyle    = [string](Get-OptionalPropertyValue $disk 'PartitionStyle')
            OperationalStatus = (@(Get-OptionalPropertyValue $disk 'OperationalStatus' @()) -join '; ')
            HealthStatus      = [string](Get-OptionalPropertyValue $disk 'HealthStatus')
            Size              = Get-OptionalPropertyValue $disk 'Size' ''
            BusType           = [string](Get-OptionalPropertyValue $disk 'BusType')
            IsBoot            = Get-OptionalPropertyValue $disk 'IsBoot' ''
            IsSystem          = Get-OptionalPropertyValue $disk 'IsSystem' ''
            IsOffline         = Get-OptionalPropertyValue $disk 'IsOffline' ''
            IsReadOnly        = Get-OptionalPropertyValue $disk 'IsReadOnly' ''
            Location          = [string](Get-OptionalPropertyValue $disk 'Location')
        }
    }

    return [PSCustomObject]@{ Volumes=@($volumeRows); Disks=@($diskRows) }
}

function Get-LocalAccountInventory {
    $localUsers = @(Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction Stop)
    $localGroups = @(Get-CimInstance -ClassName Win32_Group -Filter "LocalAccount=True" -ErrorAction Stop)
    $administratorsGroup = $localGroups | Where-Object { [string]$_.SID -eq 'S-1-5-32-544' } | Select-Object -First 1
    if ($null -eq $administratorsGroup) {
        throw 'Local Administrators group (S-1-5-32-544) was not found'
    }
    $members = @(Get-CimAssociatedInstance -InputObject $administratorsGroup `
        -Association Win32_GroupUser -ErrorAction Stop)

    $userRows = foreach ($user in $localUsers) {
        [PSCustomObject]@{
            Name               = [string]$user.Name
            Domain             = [string]$user.Domain
            SID                = [string]$user.SID
            Description        = [string]$user.Description
            FullName           = [string]$user.FullName
            Disabled           = [bool]$user.Disabled
            Lockout            = [bool]$user.Lockout
            PasswordRequired   = [bool]$user.PasswordRequired
            PasswordChangeable = [bool]$user.PasswordChangeable
            PasswordExpires    = [bool]$user.PasswordExpires
            AccountType        = [string]$user.AccountType
            Status             = [string]$user.Status
        }
    }

    $memberRows = foreach ($member in $members) {
        $domain = [string](Get-OptionalPropertyValue $member 'Domain')
        $name = [string](Get-OptionalPropertyValue $member 'Name')
        $sid = [string](Get-OptionalPropertyValue $member 'SID')
        $sidType = [string](Get-OptionalPropertyValue $member 'SIDType')
        $isLocal = ((Get-OptionalPropertyValue $member 'LocalAccount' $false) -eq $true -or
            $domain -ieq $env:COMPUTERNAME)
        [PSCustomObject]@{
            GroupName   = [string]$administratorsGroup.Name
            GroupSID    = 'S-1-5-32-544'
            AccountName = if ([string]::IsNullOrWhiteSpace($domain)) { $name } else { "$domain\$name" }
            Domain      = $domain
            Name        = $name
            SID         = $sid
            SIDType     = $sidType
            IsLocal     = [bool]$isLocal
        }
    }

    return [PSCustomObject]@{ Users=@($userRows); Administrators=@($memberRows) }
}

function Get-Sha256Hex {
    param([string]$Value, $Provider = $null)
    $sha = $Provider
    $ownsProvider = $false
    if ($null -eq $sha) {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $ownsProvider = $true
    }
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
        return [System.BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant()
    } finally {
        if ($ownsProvider) { $sha.Dispose() }
    }
}

function Get-NormalizedDaclSddl {
    param([string]$Sddl)
    if ([string]::IsNullOrWhiteSpace($Sddl) -or -not $Sddl.StartsWith('D:')) { return $Sddl }
    $aceStart = $Sddl.IndexOf('(')
    if ($aceStart -lt 0) {
        $flags = $Sddl.Substring(2)
        $aces = ''
    } else {
        $flags = $Sddl.Substring(2, $aceStart - 2)
        $aces = $Sddl.Substring($aceStart)
    }
    $protection = if ($flags -match 'P') { 'P' } else { '' }
    return "D:$protection$aces"
}

function Export-FsrmNativeXml {
    param(
        [string]$CommandName,
        [string]$ObjectType,
        [string]$OutputPath
    )

    $command = Get-Command -Name $CommandName -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $command) {
        Write-Log "WARN : $CommandName not found - native FSRM XML export unavailable for $ObjectType." "WARN"
        return $false
    }

    $temporaryPath = $OutputPath + '.PRODTEST_tmp_' + [Guid]::NewGuid().ToString('N')
    try {
        $nativeOutput = & $command $ObjectType 'export' ("/file:{0}" -f $temporaryPath) 2>&1
        $nativeExitCode = 0
        if ($command.CommandType -eq [System.Management.Automation.CommandTypes]::Application) {
            $nativeExitCode = $LASTEXITCODE
        }
        if ($nativeExitCode -ne 0) {
            throw "$CommandName exited with code $nativeExitCode : $($nativeOutput -join ' ')"
        }
        if (-not (Test-Path -LiteralPath $temporaryPath -PathType Leaf)) {
            throw "$CommandName did not create the expected XML file"
        }
        $temporaryItem = Get-Item -LiteralPath $temporaryPath -ErrorAction Stop
        if ($temporaryItem.Length -le 0) { throw 'native XML file is empty' }

        $xmlDocument = New-Object System.Xml.XmlDocument
        $xmlDocument.Load($temporaryPath)
        Move-Item -LiteralPath $temporaryPath -Destination $OutputPath -Force
        Write-Log ("FSRM native XML exported : {0}" -f (Split-Path $OutputPath -Leaf))
        return $true
    } catch {
        Write-Log "WARN : native FSRM XML export failed for $ObjectType : $_" "WARN"
        return $false
    } finally {
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
        }
    }
}

#endregion

# ---------------------------------------------------------------------------
# Step selection logic
# ---------------------------------------------------------------------------
function Show-Menu {
    $selected = @{}
    foreach ($id in $STEP_IDS) { $selected[$id] = $true }

    while ($true) {
        Clear-Host
        Write-Host ""
        Write-Host "  =============================================" -ForegroundColor Cyan
        Write-Host "    FileServer Export  -  Step Selection" -ForegroundColor Cyan
        Write-Host "  =============================================" -ForegroundColor Cyan
        Write-Host ""

        $i = 1
        foreach ($id in $STEP_IDS) {
            $check = if ($selected[$id]) { '[X]' } else { '[ ]' }
            $color = if ($selected[$id]) { 'Green' } else { 'DarkGray' }
            Write-Host ("  {0} {1}  {2}" -f $check, $i, $STEP_LABELS[$id]) -ForegroundColor $color
            $i++
        }

        Write-Host ""
        Write-Host ("  Commands : 1-{0} toggle  |  A select all  |  N deselect all  |  R run" -f $STEP_IDS.Count) -ForegroundColor DarkCyan
        Write-Host ""
        $choice = (Read-Host "  Choice").Trim().ToUpper()

        if ($choice -eq 'R') {
            $anySelected = $false
            foreach ($id in $STEP_IDS) { if ($selected[$id]) { $anySelected = $true; break } }
            if (-not $anySelected) {
                Write-Host "  No step selected. Select at least one." -ForegroundColor Red
                Start-Sleep -Seconds 2
                continue
            }
            break
        }
        elseif ($choice -eq 'A') {
            foreach ($id in $STEP_IDS) { $selected[$id] = $true }
        }
        elseif ($choice -eq 'N') {
            foreach ($id in $STEP_IDS) { $selected[$id] = $false }
        }
        else {
            $tokens = $choice -split '[,\s]+' | Where-Object { $_ -ne '' }
            foreach ($token in $tokens) {
                $n = 0
                if ([int]::TryParse($token, [ref]$n) -and $n -ge 1 -and $n -le $STEP_IDS.Count) {
                    $id = $STEP_IDS[$n - 1]
                    $selected[$id] = -not $selected[$id]
                }
            }
        }
    }

    return $selected
}

function Resolve-Steps {
    $run = @{}
    foreach ($id in $STEP_IDS) { $run[$id] = $false }

    if ($Interactive) {
        $run = Show-Menu
    }
    elseif ($Steps -and $Steps.Count -gt 0) {
        foreach ($s in $Steps) {
            $match = $STEP_IDS | Where-Object { $_ -ieq $s }
            if ($match) {
                $run[$match] = $true
            } else {
                Write-Warning "Unknown step '$s'. Valid values: $($STEP_IDS -join ', ')"
            }
        }
    }
    else {
        # Default: run all
        foreach ($id in $STEP_IDS) { $run[$id] = $true }
    }

    return $run
}

# ---------------------------------------------------------------------------
# Init
# ---------------------------------------------------------------------------
$exportRootWasNonEmpty = $false
if (-not $PSBoundParameters.ContainsKey('ExportRoot')) {
    $automaticExportRoot = $ExportRoot
    $automaticSuffix = 2
    while (Test-Path -LiteralPath $ExportRoot) {
        $ExportRoot = "${automaticExportRoot}_$automaticSuffix"
        $automaticSuffix++
    }
}
if (Test-Path -LiteralPath $ExportRoot) {
    $rootItem = Get-Item -LiteralPath $ExportRoot -ErrorAction Stop
    if (-not $rootItem.PSIsContainer) {
        throw "ExportRoot exists but is not a directory : $ExportRoot"
    }
    $firstExistingItem = Get-ChildItem -LiteralPath $ExportRoot -Force -ErrorAction Stop | Select-Object -First 1
    if ($null -ne $firstExistingItem) {
        $exportRootWasNonEmpty = $true
        if (-not $AllowExistingExportRoot) {
            throw "ExportRoot is not empty. Use a new folder, or explicitly pass -AllowExistingExportRoot : $ExportRoot"
        }
    }
}
Ensure-Dir $ExportRoot
$ExportRoot = (Resolve-Path $ExportRoot).Path

$run = Resolve-Steps

# ---------------------------------------------------------------------------
# Remote/explicit mode (-Paths / -ComputerName) : only ACLs + Inheritance make
# sense against remote targets - the other steps read local server state.
# ---------------------------------------------------------------------------
$remoteMode   = (($null -ne $Paths -and @($Paths).Count -gt 0) -or $ComputerName -ne "")
$droppedSteps = @()
if ($remoteMode) {
    $droppedSteps = @($STEP_IDS | Where-Object { $run[$_] -and $_ -ne 'ACLs' -and $_ -ne 'Inheritance' })
    foreach ($id in $droppedSteps) { $run[$id] = $false }
    if (-not $run['ACLs'] -and -not $run['Inheritance']) {
        $run['ACLs']        = $true
        $run['Inheritance'] = $true
    }
}

Clear-Host
Write-Host ""
Write-Host "  =====================================================" -ForegroundColor Cyan
Write-Host "    FileServer Export  -  $env:COMPUTERNAME" -ForegroundColor Cyan
Write-Host "  =====================================================" -ForegroundColor Cyan
Write-Host ""

$runList = @($STEP_IDS | Where-Object { $run[$_] })
Write-Host ("  Steps selected : {0}" -f ($runList -join ', ')) -ForegroundColor White
Write-Host ("  Output folder  : {0}" -f $ExportRoot) -ForegroundColor White
Write-Host ("  Excluded drives: {0}" -f ($ExcludeDrives -join ', ')) -ForegroundColor White
Write-Host ""

Write-Log "=== Export started on $env:COMPUTERNAME ==="
Write-Log ("PowerShell {0} (hot paths are pure .NET - same speed on PS4 and PS5+)" -f $PSVersionTable.PSVersion)
Write-Log ("Steps : {0}" -f ($runList -join ', '))
Write-Log ("Export folder : $ExportRoot")
Write-Log ("Excluded drives : {0}" -f ($ExcludeDrives -join ', '))
if ($exportRootWasNonEmpty) {
    Write-Log "Existing non-empty export folder explicitly allowed - stale files may be present : $ExportRoot" "WARN"
}
if ($remoteMode -and $droppedSteps.Count -gt 0) {
    Write-Log ("Remote mode (-Paths/-ComputerName) : steps not applicable, dropped : {0}" -f ($droppedSteps -join ', ')) "WARN"
}

# ---------------------------------------------------------------------------
# Build the target list : local SMB shares, or remote/explicit roots
# ---------------------------------------------------------------------------
if ($remoteMode) {
    $shareList = New-Object 'System.Collections.Generic.List[PSCustomObject]'

    if ($ComputerName -ne "") {
        Write-Log "Discovering shares on '$ComputerName' over CIM..."
        try {
            $cim = New-CimSession -ComputerName $ComputerName -ErrorAction Stop
            $remoteShares = Get-SmbShare -CimSession $cim | Where-Object { -not $_.Special }
            Remove-CimSession $cim
            foreach ($rs in $remoteShares) {
                $shareList.Add([PSCustomObject]@{ Name = $rs.Name; Path = "\\$ComputerName\$($rs.Name)" })
            }
            Write-Log ("Shares discovered : {0}" -f (($shareList | ForEach-Object { $_.Name }) -join ', '))
        } catch {
            Write-Log "ERROR : share discovery failed on '$ComputerName' : $_" "ERROR"
        }
    }

    if ($null -ne $Paths) {
        foreach ($p in $Paths) {
            $leaf = Split-Path $p -Leaf
            if ([string]::IsNullOrWhiteSpace($leaf)) { $leaf = ($p -replace '[\\:]+', '_').Trim('_') }
            $shareList.Add([PSCustomObject]@{ Name = $leaf; Path = $p.TrimEnd('\') })
        }
    }

    $allShares = $shareList
    Write-Log ("Targets : {0}" -f (($allShares | ForEach-Object { $_.Path }) -join ' | '))
} else {
    # Pre-load local SMB shares (needed by Shares + ACLs steps, fast read)
    $allShares = Get-SmbShare | Where-Object {
        if (IsExcludedDrive $_.Path) { return $false }
        if ($ExcludeHiddenShares -and $_.Name -match '\$$') { return $false }
        return $true
    }

    $skipped = Get-SmbShare | Where-Object { IsExcludedDrive $_.Path }
    if ($skipped) {
        Write-Log ("Shares on excluded drives (skipped) : {0}" -f (($skipped | ForEach-Object { $_.Name }) -join ', '))
    }
}

# ACL sections read by the ACLs and Inheritance steps : Owner + Group + DACL
# (no SACL - would need Get-Acl -Audit semantics + SeSecurityPrivilege)
$sddlSections = [System.Security.AccessControl.AccessControlSections]::Access -bor `
                [System.Security.AccessControl.AccessControlSections]::Owner  -bor `
                [System.Security.AccessControl.AccessControlSections]::Group

# ---------------------------------------------------------------------------
# Step 1 : SMB Shares + Share Permissions
# ---------------------------------------------------------------------------
if ($run['Shares']) {
    Write-Log "--- Step 1 : SMB Shares + Share Permissions ---"

    $allShares | Select-Object `
        Name, Path, Description, ScopeName,
        CurrentUsers, MaximumAllowed,
        CachingMode, EncryptData, FolderEnumerationMode, ContinuouslyAvailable,
        ConcurrentUserLimit,
        @{N='ShareType'; E={ $_.ShareType }},
        @{N='Special';   E={ $_.Special }} |
        Export-Csv -Path "$ExportRoot\shares.csv" -NoTypeInformation -Encoding UTF8

    Write-Log ("Shares exported : {0}" -f ($allShares | Measure-Object).Count)

    $sharePerms = foreach ($share in $allShares) {
        try {
            Get-SmbShareAccess -Name $share.Name -ErrorAction Stop | Select-Object `
                @{N='ShareName';  E={ $share.Name }},
                @{N='SharePath';  E={ $share.Path }},
                AccountName,
                @{N='AccountSid'; E={ ConvertTo-SidValue $_.AccountName }},
                AccessControlType, AccessRight
        } catch {
            Write-Log "WARN : cannot read SMB ACLs for '$($share.Name)' : $_" "WARN"
        }
    }
    $sharePerms | Export-Csv -Path "$ExportRoot\shares_permissions.csv" -NoTypeInformation -Encoding UTF8
    Write-Log ("SMB permission entries exported : {0}" -f ($sharePerms | Measure-Object).Count)
}

# ---------------------------------------------------------------------------
# Step 2 : DFS Targets
# ---------------------------------------------------------------------------
if ($run['DFS']) {
    Write-Log "--- Step 2 : DFS Targets ---"

    $dfsData = @()
    if ($DfsNamespaceServer -ne "") {
        try {
            $roots = Get-DfsnRoot -ComputerName $DfsNamespaceServer -ErrorAction Stop
            foreach ($root in $roots) {
                $folders = Get-DfsnFolder -Path ($root.Path + "\*") -ErrorAction SilentlyContinue
                foreach ($folder in $folders) {
                    $targets = Get-DfsnFolderTarget -Path $folder.Path -ErrorAction SilentlyContinue
                    foreach ($target in $targets) {
                        $dfsData += [PSCustomObject]@{
                            NamespacePath         = $folder.Path
                            TargetPath            = $target.TargetPath
                            State                 = $target.State
                            ReferralPriorityClass = $target.ReferralPriorityClass
                            ReferralPriorityRank  = $target.ReferralPriorityRank
                        }
                    }
                }
            }
            $dfsData | Export-Csv -Path "$ExportRoot\dfs_targets.csv" -NoTypeInformation -Encoding UTF8
            Write-Log ("DFS targets exported : {0}" -f $dfsData.Count)
        } catch {
            Write-Log "WARN : DFS export failed (RSAT DFS required or wrong -DfsNamespaceServer) : $_" "WARN"
            if (Get-Command dfsutil.exe -ErrorAction SilentlyContinue) {
                Write-Log "Fallback via dfsutil..."
                & dfsutil.exe /root:\\$DfsNamespaceServer\* /view 2>&1 |
                    Out-File "$ExportRoot\dfs_dfsutil.txt" -Encoding UTF8
            }
        }
    } else {
        Write-Log "WARN : -DfsNamespaceServer not provided - re-run with -DfsNamespaceServer HOSTNAME" "WARN"
        $localRoots = $null
        if (Get-Command Get-DfsnRoot -ErrorAction SilentlyContinue) {
            $localRoots = Get-DfsnRoot -ComputerName $env:COMPUTERNAME -ErrorAction SilentlyContinue
        } else {
            Write-Log "WARN : Get-DfsnRoot not available - install RSAT DFS Namespaces feature" "WARN"
        }
        if ($localRoots) {
            $localRoots | Export-Csv -Path "$ExportRoot\dfs_local_roots.csv" -NoTypeInformation -Encoding UTF8
            Write-Log ("Local DFS namespaces exported : {0}" -f ($localRoots | Measure-Object).Count)
        }
    }
}

# ---------------------------------------------------------------------------
# Step 3 : NTFS ACLs
# ---------------------------------------------------------------------------
if ($run['ACLs']) {
    if ($FullACLBackup) {
        Write-Log "--- Step 3 : NTFS ACLs - FULL mode (icacls /save /T, folders + files) ---"
    } else {
        Write-Log "--- Step 3 : NTFS ACLs - folders only (SDDL CSV + icacls share roots) ---"
    }

    $aclSummary     = New-Object 'System.Collections.Generic.List[PSCustomObject]'
    $processedPaths = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([StringComparer]::OrdinalIgnoreCase)

    $enumErrFile      = "$ExportRoot\acls_enum_errors.txt"
    $totalDirsScanned = 0
    $totalRowsWritten = 0
    $totalAclErrors   = 0
    $totalCsvFiles    = 0

    # When the Inheritance step is also selected, this walk emits inheritance_map.csv
    # in the same pass : step 3b then has nothing left to scan.
    $mergeInheritance = ($run['Inheritance'] -and -not $FullACLBackup)
    $inhWriter        = $null
    $inhHashProvider  = $null
    $totalInhRows     = 0
    $totalInhBroken   = 0

    # The walk must go deep enough for both outputs
    $walkDepth = $FolderAclDepth
    if ($mergeInheritance) {
        if ($InheritanceCheckDepth -lt 0) {
            $walkDepth = -1
        } elseif ($walkDepth -ge 0 -and $InheritanceCheckDepth -gt $walkDepth) {
            $walkDepth = $InheritanceCheckDepth
        }
    }

    if ($mergeInheritance) {
        Write-Log ("Inheritance map will be emitted by the same walk (merged, depth<={0})" -f $InheritanceCheckDepth)
        $inhWriter = New-Object System.IO.StreamWriter("$ExportRoot\inheritance_map.csv", $false, (New-Object System.Text.UTF8Encoding($true)))
        $inhHashProvider = [System.Security.Cryptography.SHA256]::Create()
        $inhWriter.WriteLine('"ShareRoot","Path","Depth","InheritanceEnabled","BrokenInheritance","ExplicitACECount","InheritedACECount","Owner","DaclSha256"')
    }

    # Two shares whose names sanitize to the same file name must not overwrite each other
    $usedSafeNames = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([StringComparer]::OrdinalIgnoreCase)

    foreach ($share in $allShares) {
        $sharePath = $share.Path
        if ([string]::IsNullOrWhiteSpace($sharePath)) { continue }
        if (-not (Test-Path $sharePath -ErrorAction SilentlyContinue)) {
            Write-Log "WARN : path not found for share '$($share.Name)' -> '$sharePath'" "WARN"
            continue
        }
        if ($processedPaths.Contains($sharePath)) {
            Write-Log "INFO : '$sharePath' already exported - share '$($share.Name)' skipped"
            continue
        }
        [void]$processedPaths.Add($sharePath)

        $safeName = Get-SafeName $share.Name
        $baseSafe = $safeName
        $suffix   = 2
        while ($usedSafeNames.Contains($safeName)) {
            $safeName = "${baseSafe}_$suffix"
            $suffix++
        }
        [void]$usedSafeNames.Add($safeName)
        if ($safeName -ne $baseSafe) {
            Write-Log "WARN : share name collision after sanitization - '$($share.Name)' exported as '$safeName'" "WARN"
        }

        if ($FullACLBackup) {
            # Legacy mode : full recursive save, folders + files (slow, fully restorable)
            $aclFile = "$ExportRoot\acls_${safeName}.bin"
            Write-Log "icacls /save /T : '$sharePath' -> acls_${safeName}.bin"
            $result   = & icacls.exe $sharePath /save $aclFile /T /C 2>&1
            $exitCode = $LASTEXITCODE
            if ($exitCode -ne 0) {
                Write-Log "WARN : icacls /save returned $exitCode for '$sharePath'" "WARN"
                Add-Content "$ExportRoot\summary.txt" ($result -join "`n") -Encoding UTF8
            }
        } else {
            # Safety net : non-recursive native save of the share root (instant, icacls /restore compatible)
            $aclFile = "$ExportRoot\acls_root_${safeName}.bin"
            Write-Log "icacls /save (root only) : '$sharePath' -> acls_root_${safeName}.bin"
            $result   = & icacls.exe $sharePath /save $aclFile /C 2>&1
            $exitCode = $LASTEXITCODE
            if ($exitCode -ne 0) {
                Write-Log "WARN : icacls /save returned $exitCode for '$sharePath'" "WARN"
                Add-Content "$ExportRoot\summary.txt" ($result -join "`n") -Encoding UTF8
            }
        }

        # Root ACL summary CSV (both modes - used by the Compare script)
        try {
            $acl = Get-Acl -Path $sharePath
            $rootOwnerSid = ConvertTo-SidValue $acl.Owner
            $rootGroupSid = ConvertTo-SidValue $acl.Group
            foreach ($ace in $acl.Access) {
                $aclSummary.Add([PSCustomObject]@{
                    ShareName               = $share.Name
                    Path                    = $sharePath
                    IdentityReference       = $ace.IdentityReference
                    IdentitySid             = ConvertTo-SidValue $ace.IdentityReference
                    FileSystemRights        = $ace.FileSystemRights
                    AccessControlType       = $ace.AccessControlType
                    IsInherited             = $ace.IsInherited
                    InheritanceFlags        = $ace.InheritanceFlags
                    PropagationFlags        = $ace.PropagationFlags
                    Owner                   = $acl.Owner
                    OwnerSid                = $rootOwnerSid
                    Group                   = $acl.Group
                    GroupSid                = $rootGroupSid
                    AreAccessRulesProtected = $acl.AreAccessRulesProtected
                })
            }
        } catch {
            Write-Log "WARN : Get-Acl failed for '$sharePath' : $_" "WARN"
        }

        if (-not $FullACLBackup) {
            # Folder-only deep scan, pure .NET for speed on very large trees (1M+ folders) :
            #   Directory.EnumerateDirectories - streaming enumeration, no PSObject wrapping
            #   DirectoryInfo.GetAccessControl - direct syscall instead of Get-Acl
            #   StreamWriter + hand-built CSV   - Export-Csv serialization is far too slow
            # Default output : only folders that carry ACL information (broken inheritance or
            # explicit ACEs) plus the share root - a purely inherited ACL is reconstructible
            # by propagation. -AllFolderAcls writes every folder.
            # Scan stops at -FolderAclDepth levels below the root (-1 = unlimited).
            Write-Log "Folder ACL scan : '$sharePath' ($aclDepthTxt, folders only)..."
            $sw         = [System.Diagnostics.Stopwatch]::StartNew()
            $shareDirs  = 0
            $shareRows  = 0
            $shareErrs  = 0

            $folderCsvPath = "$ExportRoot\acls_folders_${safeName}.csv"
            $writer = New-Object System.IO.StreamWriter($folderCsvPath, $false, (New-Object System.Text.UTF8Encoding($true)))

            # Stack items : 2-element array (path, depth below share root)
            $stack = New-Object System.Collections.Stack
            $stack.Push(@($sharePath, 0))

            try {
                $writer.WriteLine('"ShareName","ShareRoot","Path","Owner","Sddl","Protected","ExplicitACEs"')

                while ($stack.Count -gt 0) {
                    $item    = $stack.Pop()
                    $current = [string]$item[0]
                    $depth   = [int]$item[1]
                    $shareDirs++

                    # Never descend INTO a junction/reparse point (cycle protection) -
                    # the junction folder itself still gets its ACL row below.
                    # The share root is always followed even if it is a mount point.
                    $descend = ($walkDepth -lt 0 -or $depth -lt $walkDepth)
                    if ($descend -and $depth -gt 0) {
                        try {
                            $attrs = [System.IO.File]::GetAttributes($current)
                            if (($attrs -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                                $descend = $false
                                Add-Content -Path $enumErrFile -Encoding UTF8 `
                                    -Value ("JUNCTION (not followed) : {0}" -f $current)
                            }
                        } catch { }
                    }

                    if ($descend) {
                        try {
                            foreach ($childPath in [System.IO.Directory]::EnumerateDirectories($current)) {
                                # Parentheses required : the comma operator binds tighter than +,
                                # @(a, $d + 1) would build a 3-element array (a, $d, 1)
                                $stack.Push(@($childPath, ($depth + 1)))
                            }
                        } catch {
                            $shareErrs++
                            Add-Content -Path $enumErrFile -Encoding UTF8 `
                                -Value ("ENUM   : {0} : {1}" -f $current, $_.Exception.Message)
                        }
                    }

                    try {
                        $di  = New-Object System.IO.DirectoryInfo($current)
                        $sec = $di.GetAccessControl($sddlSections)

                        $protected = $sec.AreAccessRulesProtected
                        $explicit  = $sec.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]).Count
                        $ownerName = $null   # resolved lazily, shared by the ACL row and the inheritance row

                        $writeAclRow = (($FolderAclDepth -lt 0 -or $depth -le $FolderAclDepth) -and `
                                        ($AllFolderAcls -or $depth -eq 0 -or $protected -or $explicit -gt 0))

                        if ($writeAclRow) {
                            if ($null -eq $ownerName) {
                                try   { $ownerName = $sec.GetOwner([System.Security.Principal.NTAccount]).Value }
                                catch { $ownerName = $sec.GetOwner([System.Security.Principal.SecurityIdentifier]).Value }
                            }
                            $writer.WriteLine(('{0},{1},{2},{3},{4},{5},{6}' -f `
                                (ConvertTo-CsvField $share.Name), `
                                (ConvertTo-CsvField $sharePath), `
                                (ConvertTo-CsvField $current), `
                                (ConvertTo-CsvField $ownerName), `
                                (ConvertTo-CsvField ($sec.GetSecurityDescriptorSddlForm($sddlSections))), `
                                $protected, $explicit))
                            $shareRows++
                        }

                        if ($mergeInheritance -and ($InheritanceCheckDepth -lt 0 -or $depth -le $InheritanceCheckDepth)) {
                            if ($null -eq $ownerName) {
                                try   { $ownerName = $sec.GetOwner([System.Security.Principal.NTAccount]).Value }
                                catch { $ownerName = $sec.GetOwner([System.Security.Principal.SecurityIdentifier]).Value }
                            }
                            $inherited = $sec.GetAccessRules($false, $true, [System.Security.Principal.SecurityIdentifier]).Count
                            $daclHash = Get-Sha256Hex (Get-NormalizedDaclSddl $sec.GetSecurityDescriptorSddlForm('Access')) $inhHashProvider
                            $inhWriter.WriteLine(('{0},{1},{2},{3},{4},{5},{6},{7},{8}' -f `
                                (ConvertTo-CsvField $sharePath), `
                                (ConvertTo-CsvField $current), `
                                $depth, (-not $protected), $protected, $explicit, $inherited, `
                                (ConvertTo-CsvField $ownerName), (ConvertTo-CsvField $daclHash)))
                            $totalInhRows++
                            if ($protected) { $totalInhBroken++ }
                        }
                    } catch {
                        $shareErrs++
                        Add-Content -Path $enumErrFile -Encoding UTF8 `
                            -Value ("GETACL : {0} : {1}" -f $current, $_.Exception.Message)
                    }

                    if (($shareDirs % 5000) -eq 0) {
                        Write-Progress -Activity "Folder ACL scan" `
                            -Status ("{0} : {1} folders scanned, {2} rows written" -f $sharePath, $shareDirs, $shareRows)
                    }
                }
            } finally {
                $writer.Close()
            }

            $sw.Stop()
            Write-Log ("Folder ACLs '{0}' : {1} folders scanned, {2} rows written in {3}s ({4} errors) -> acls_folders_{5}.csv" -f `
                $share.Name, $shareDirs, $shareRows, [math]::Round($sw.Elapsed.TotalSeconds, 1), $shareErrs, $safeName)
            $totalDirsScanned += $shareDirs
            $totalRowsWritten += $shareRows
            $totalAclErrors   += $shareErrs
            $totalCsvFiles++
        }
    }

    if (-not $FullACLBackup) {
        Write-Progress -Activity "Folder ACL scan" -Completed
    }

    if ($null -ne $inhWriter) {
        $inhWriter.Close()
        $inhHashProvider.Dispose()
        Write-Log ("Inheritance map (merged with ACLs walk) : {0} dirs (depth<={1}), {2} with broken inheritance -> inheritance_map.csv" -f `
            $totalInhRows, $InheritanceCheckDepth, $totalInhBroken)
    }

    $aclSummary | Export-Csv -Path "$ExportRoot\acls_roots.csv" -NoTypeInformation -Encoding UTF8
    Write-Log ("NTFS root ACL entries exported : {0}" -f $aclSummary.Count)

    if (-not $FullACLBackup) {
        Write-Log ("Folder ACLs total : {0} folders scanned, {1} rows written in {2} acls_folders_*.csv files ({3} errors, see acls_enum_errors.txt)" -f `
            $totalDirsScanned, $totalRowsWritten, $totalCsvFiles, $totalAclErrors)

        # Restore helper : DACL-only reapply from CSV, streamed, dry-run by default.
        $restoreScript = @'
#Requires -Version 4.0
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Re-apply folder DACLs from the acls_folders_NAME.csv files (one per share)
    generated by Export-FileServer-BeforeMigration.ps1.
    Unless the export was made with -AllFolderAcls, the CSVs only contain folders
    carrying ACL information (broken inheritance or explicit ACEs) plus the share
    root : restoring those is sufficient, NTFS inheritance propagates the rest.
    DACL-only via DirectoryInfo.SetAccessControl (Access section) : owner and SACL are
    never touched, so neither SeRestorePrivilege nor SeSecurityPrivilege is required.
    CSVs are streamed row by row - flat memory usage even on low-RAM servers.
    Dry-run by default - nothing is written unless -Apply is set.

.EXAMPLE
    .\Restore-FolderAcls.ps1                                    # dry-run, every acls_folders*.csv next to the script
    .\Restore-FolderAcls.ps1 -CsvPath .\acls_folders_DATA.csv   # dry-run, one share only
    .\Restore-FolderAcls.ps1 -PathFilter 'E:\Data\HR*'          # dry-run, scoped by path
    .\Restore-FolderAcls.ps1 -PathFilter 'E:\Data\HR*' -Apply   # actually restore
#>
param(
    [string]$CsvPath = '',
    [string]$PathFilter = '*',
    [switch]$Apply
)

function Get-NormalizedDaclSddl {
    param([string]$Sddl)
    if ([string]::IsNullOrWhiteSpace($Sddl) -or -not $Sddl.StartsWith('D:')) { return $Sddl }
    $aceStart = $Sddl.IndexOf('(')
    if ($aceStart -lt 0) {
        $flags = $Sddl.Substring(2); $aces = ''
    } else {
        $flags = $Sddl.Substring(2, $aceStart - 2); $aces = $Sddl.Substring($aceStart)
    }
    $protection = if ($flags -match 'P') { 'P' } else { '' }
    return "D:$protection$aces"
}

if ($CsvPath -ne '') {
    $csvFiles = @(Get-ChildItem $CsvPath -ErrorAction SilentlyContinue)
} else {
    $csvFiles = @(Get-ChildItem "$PSScriptRoot\acls_folders*.csv" -ErrorAction SilentlyContinue)
}
if ($csvFiles.Count -eq 0) { Write-Error "No acls_folders*.csv file found"; exit 1 }

$accessOnly = [System.Security.AccessControl.AccessControlSections]::Access
$same = 0; $restored = 0; $failed = 0; $missing = 0

foreach ($csvFile in $csvFiles) {
    Write-Host "--- $($csvFile.Name) ---"
    # Import-Csv in a pipeline streams row by row : the file is never fully loaded in RAM
    Import-Csv $csvFile.FullName | ForEach-Object {
        $r = $_
        if ($r.Path -notlike $PathFilter) { return }
        $di = $null
        try { $di = New-Object System.IO.DirectoryInfo($r.Path) } catch { }
        if ($null -eq $di -or -not $di.Exists) { $missing++; return }

        $idx = $r.Sddl.IndexOf('D:')
        if ($idx -lt 0) { return }
        $daclSddl = $r.Sddl.Substring($idx)

        try {
            $sec = $di.GetAccessControl('Access')
            if ((Get-NormalizedDaclSddl $sec.GetSecurityDescriptorSddlForm('Access')) -eq `
                (Get-NormalizedDaclSddl $daclSddl)) { $same++; return }
            if ($Apply) {
                # Two-argument overload is mandatory : without the Access section restriction,
                # SetSecurityDescriptorSddlForm marks ALL sections modified (incl. SACL) and the
                # write then fails with PrivilegeNotHeldException (SeSecurityPrivilege).
                $sec.SetSecurityDescriptorSddlForm($daclSddl, $accessOnly)
                $di.SetAccessControl($sec)
                $verifySec = $di.GetAccessControl('Access')
                $verify = $verifySec.GetSecurityDescriptorSddlForm('Access')
                if ((Get-NormalizedDaclSddl $verify) -ne (Get-NormalizedDaclSddl $daclSddl)) {
                    throw 'DACL verification after write failed'
                }
                Write-Host "RESTORED      : $($r.Path)" -ForegroundColor Cyan
            } else {
                Write-Host "WOULD RESTORE : $($r.Path)" -ForegroundColor Yellow
            }
            $restored++
        } catch {
            $failed++
            Write-Host "FAILED        : $($r.Path) : $_" -ForegroundColor Red
        }
    }
}

$mode = if ($Apply) { 'APPLY' } else { 'DRY-RUN' }
Write-Host ""
Write-Host "[$mode] identical: $same | to restore/restored: $restored | failed: $failed | path missing: $missing"
'@
        $restoreScript | Out-File "$ExportRoot\Restore-FolderAcls.ps1" -Encoding UTF8
        Write-Log "Restore helper written : Restore-FolderAcls.ps1 (DACL-only, dry-run by default)"
    }
}

# ---------------------------------------------------------------------------
# Step 3b : NTFS Inheritance Map
# ---------------------------------------------------------------------------
if ($run['Inheritance']) {
    if ($run['ACLs'] -and -not $FullACLBackup) {
        Write-Log "--- Step 3b : NTFS Inheritance map - already emitted by the ACLs step walk (merged), nothing to scan ---"
    } else {
        # Standalone scan (-Steps Inheritance alone, or ACLs in -FullACLBackup mode).
        # Same pure .NET walk as the ACLs step : EnumerateDirectories + GetAccessControl + StreamWriter.
        Write-Log ("--- Step 3b : NTFS Inheritance map (standalone scan, depth={0}) ---" -f $InheritanceCheckDepth)

        $inhErrFile   = "$ExportRoot\acls_enum_errors.txt"
        $scannedRoots = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([StringComparer]::OrdinalIgnoreCase)
        $inhDirs = 0; $inhBroken = 0; $inhErrs = 0

        $inhW = New-Object System.IO.StreamWriter("$ExportRoot\inheritance_map.csv", $false, (New-Object System.Text.UTF8Encoding($true)))
        $standaloneHashProvider = [System.Security.Cryptography.SHA256]::Create()
        try {
            $inhW.WriteLine('"ShareRoot","Path","Depth","InheritanceEnabled","BrokenInheritance","ExplicitACECount","InheritedACECount","Owner","DaclSha256"')

            foreach ($share in $allShares) {
                $sharePath = $share.Path
                if ([string]::IsNullOrWhiteSpace($sharePath)) { continue }
                if (-not (Test-Path $sharePath -ErrorAction SilentlyContinue)) { continue }
                if ($scannedRoots.Contains($sharePath)) { continue }
                [void]$scannedRoots.Add($sharePath)

                Write-Log "Inheritance scan : '$sharePath' (depth $InheritanceCheckDepth)..."

                $stack = New-Object System.Collections.Stack
                $stack.Push(@($sharePath, 0))

                while ($stack.Count -gt 0) {
                    $item    = $stack.Pop()
                    $current = [string]$item[0]
                    $depth   = [int]$item[1]
                    $inhDirs++

                    # Same junction/cycle protection as the ACLs step walk
                    $descend = ($InheritanceCheckDepth -lt 0 -or $depth -lt $InheritanceCheckDepth)
                    if ($descend -and $depth -gt 0) {
                        try {
                            $attrs = [System.IO.File]::GetAttributes($current)
                            if (($attrs -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                                $descend = $false
                                Add-Content -Path $inhErrFile -Encoding UTF8 `
                                    -Value ("JUNCTION (not followed) : {0}" -f $current)
                            }
                        } catch { }
                    }

                    if ($descend) {
                        try {
                            foreach ($childPath in [System.IO.Directory]::EnumerateDirectories($current)) {
                                # Parentheses required : comma binds tighter than + (see ACLs step)
                                $stack.Push(@($childPath, ($depth + 1)))
                            }
                        } catch {
                            $inhErrs++
                            Add-Content -Path $inhErrFile -Encoding UTF8 `
                                -Value ("ENUM   : {0} : {1}" -f $current, $_.Exception.Message)
                        }
                    }

                    try {
                        $sec = (New-Object System.IO.DirectoryInfo($current)).GetAccessControl($sddlSections)
                        $protected = $sec.AreAccessRulesProtected
                        $explicit  = $sec.GetAccessRules($true,  $false, [System.Security.Principal.SecurityIdentifier]).Count
                        $inherited = $sec.GetAccessRules($false, $true,  [System.Security.Principal.SecurityIdentifier]).Count
                        $ownerName = ''
                        try   { $ownerName = $sec.GetOwner([System.Security.Principal.NTAccount]).Value }
                        catch { $ownerName = $sec.GetOwner([System.Security.Principal.SecurityIdentifier]).Value }
                        $daclHash = Get-Sha256Hex (Get-NormalizedDaclSddl $sec.GetSecurityDescriptorSddlForm('Access')) $standaloneHashProvider

                        $inhW.WriteLine(('{0},{1},{2},{3},{4},{5},{6},{7},{8}' -f `
                            (ConvertTo-CsvField $sharePath), `
                            (ConvertTo-CsvField $current), `
                            $depth, (-not $protected), $protected, $explicit, $inherited, `
                            (ConvertTo-CsvField $ownerName), (ConvertTo-CsvField $daclHash)))
                        if ($protected) { $inhBroken++ }
                    } catch {
                        $inhErrs++
                        Add-Content -Path $inhErrFile -Encoding UTF8 `
                            -Value ("GETACL : {0} : {1}" -f $current, $_.Exception.Message)
                    }

                    if (($inhDirs % 5000) -eq 0) {
                        Write-Progress -Activity "Inheritance scan" `
                            -Status ("{0} : {1} folders scanned" -f $sharePath, $inhDirs)
                    }
                }
            }
        } finally {
            $inhW.Close()
            $standaloneHashProvider.Dispose()
        }

        Write-Progress -Activity "Inheritance scan" -Completed
        Write-Log ("Inheritance map : {0} dirs scanned, {1} with broken inheritance, {2} errors -> inheritance_map.csv" -f `
            $inhDirs, $inhBroken, $inhErrs)
    }
}

# ---------------------------------------------------------------------------
# Step 4 : Volumes and Disks
# ---------------------------------------------------------------------------
if ($run['Volumes']) {
    Write-Log "--- Step 4 : Volumes and Disks ---"
    try {
        $storageInventory = Get-StorageInventory
        $volumeColumns = @('DriveLetter','FileSystemLabel','FileSystem','DriveType','HealthStatus',
            'OperationalStatus','SizeRemaining','Size','IsDataDisk','VolumeUniqueId','VolumePath',
            'DiskNumber','PartitionNumber','PartitionGuid','PartitionOffset','PartitionSize','PartitionType',
            'DiskUniqueId','DiskSerialNumber','DiskGuid','DiskSignature','DiskFriendlyName','DiskBusType',
            'DiskSize','DiskPartitionStyle')
        $diskColumns = @('Number','FriendlyName','SerialNumber','UniqueId','Guid','Signature',
            'PartitionStyle','OperationalStatus','HealthStatus','Size','BusType','IsBoot','IsSystem',
            'IsOffline','IsReadOnly','Location')
        Export-CsvBaseline -Rows $storageInventory.Volumes -Path "$ExportRoot\volumes.csv" -Columns $volumeColumns
        Export-CsvBaseline -Rows $storageInventory.Disks -Path "$ExportRoot\disks.csv" -Columns $diskColumns
        Write-Log ("Data volumes (migrated)  : {0}" -f @($storageInventory.Volumes | Where-Object { $_.IsDataDisk -eq $true }).Count)
        Write-Log ("Other volumes (excluded) : {0}" -f @($storageInventory.Volumes | Where-Object { $_.IsDataDisk -eq $false }).Count)
        Write-Log ("Physical disks inventoried: {0}" -f @($storageInventory.Disks).Count)
    } catch {
        Write-Log "ERROR : volume/disk inventory failed : $_" "ERROR"
    }
}

# ---------------------------------------------------------------------------
# Step 5 : Local users and local Administrators membership
# ---------------------------------------------------------------------------
if ($run['LocalAccounts']) {
    Write-Log "--- Step 5 : Local users and local Administrators membership ---"
    try {
        $localAccountInventory = Get-LocalAccountInventory
        $localUserColumns = @('Name','Domain','SID','Description','FullName','Disabled','Lockout',
            'PasswordRequired','PasswordChangeable','PasswordExpires','AccountType','Status')
        $localAdministratorColumns = @('GroupName','GroupSID','AccountName','Domain','Name','SID','SIDType','IsLocal')
        Export-CsvBaseline -Rows $localAccountInventory.Users `
            -Path "$ExportRoot\local_users.csv" -Columns $localUserColumns
        Export-CsvBaseline -Rows $localAccountInventory.Administrators `
            -Path "$ExportRoot\local_administrators_members.csv" -Columns $localAdministratorColumns
        Write-Log ("Local users exported : {0}" -f @($localAccountInventory.Users).Count)
        Write-Log ("Local Administrators members exported : {0}" -f @($localAccountInventory.Administrators).Count)
        Write-Log "Passwords and password hashes are intentionally not exported"
    } catch {
        Write-Log "ERROR : local accounts inventory failed : $_" "ERROR"
    }
}

# ---------------------------------------------------------------------------
# Step 6 : Scheduled Tasks
# ---------------------------------------------------------------------------
if ($run['Tasks']) {
    Write-Log "--- Step 6 : Scheduled Tasks ---"

    $scheduledTasksDir = "$ExportRoot\scheduled_tasks"
    Ensure-Dir $scheduledTasksDir

    $allTasks = Get-ScheduledTask -ErrorAction SilentlyContinue
    $taskXmlById = @{}

    $taskRows = foreach ($t in $allTasks) {
        $info = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction SilentlyContinue
        $taskId = $t.TaskPath + [char]0 + $t.TaskName
        $taskXmlFile = "task_$(Get-Sha256Hex $taskId).xml"
        $taskXmlById[$taskId] = $taskXmlFile

        $actions = foreach ($a in $t.Actions) {
            if ($a.PSObject.Properties.Name -contains 'Execute') {
                "$($a.Execute) $($a.Arguments)".Trim()
            } else {
                $a.GetType().Name
            }
        }
        $triggers = foreach ($tr in $t.Triggers) { $tr.GetType().Name }

        [PSCustomObject]@{
            TaskName    = $t.TaskName
            TaskPath    = $t.TaskPath
            State       = $t.State
            Description = $t.Description
            Author      = $t.Principal.UserId
            AuthorSid   = ConvertTo-SidValue $t.Principal.UserId
            RunLevel    = $t.Principal.RunLevel
            LogonType   = $t.Principal.LogonType
            Actions     = $actions  -join '; '
            Triggers    = $triggers -join '; '
            NextRunTime = if ($info) { $info.NextRunTime   } else { $null }
            LastRunTime = if ($info) { $info.LastRunTime   } else { $null }
            LastResult  = if ($info) { $info.LastTaskResult} else { $null }
            TaskXmlFile = $taskXmlFile
        }
    }
    $taskRows | Export-Csv -Path "$ExportRoot\scheduled_tasks.csv" -NoTypeInformation -Encoding UTF8
    Write-Log ("Scheduled tasks exported (CSV) : {0}" -f ($taskRows | Measure-Object).Count)

    $exportedXml = 0
    foreach ($task in $allTasks) {
        try {
            $taskId  = $task.TaskPath + [char]0 + $task.TaskName
            $xmlFile = Join-Path $scheduledTasksDir $taskXmlById[$taskId]
            Export-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath |
                Out-File -FilePath $xmlFile -Encoding UTF8
            $exportedXml++
        } catch {
            Write-Log "WARN : XML export failed for task '$($task.TaskName)' : $_" "WARN"
        }
    }
    Write-Log ("Scheduled tasks exported (XML) : $exportedXml -> $scheduledTasksDir")
}

# ---------------------------------------------------------------------------
# Step 7 : FSRM
# ---------------------------------------------------------------------------
if ($run['FSRM']) {
    Write-Log "--- Step 7 : FSRM ---"

    if (-not (Get-Module -ListAvailable -Name FileServerResourceManager)) {
        $script:FsrmNativeExportStatus = 'Unavailable'
        Write-Log "WARN : module FileServerResourceManager not found - FSRM not installed, step skipped." "WARN"
    } else {
        Import-Module FileServerResourceManager -ErrorAction SilentlyContinue

        # Native Microsoft XML keeps full template notification actions. The
        # existing CSV files remain the stable comparison and compatibility layer.
        $nativeFileGroupsOk = Export-FsrmNativeXml -CommandName 'filescrn.exe' `
            -ObjectType 'filegroup' -OutputPath (Join-Path $ExportRoot 'fsrm_filegroups.xml')
        $nativeScreenTemplatesOk = Export-FsrmNativeXml -CommandName 'filescrn.exe' `
            -ObjectType 'template' -OutputPath (Join-Path $ExportRoot 'fsrm_screen_templates.xml')
        $nativeQuotaTemplatesOk = Export-FsrmNativeXml -CommandName 'dirquota.exe' `
            -ObjectType 'template' -OutputPath (Join-Path $ExportRoot 'fsrm_quota_templates.xml')
        if ($nativeFileGroupsOk -and $nativeScreenTemplatesOk -and $nativeQuotaTemplatesOk) {
            $script:FsrmNativeExportStatus = 'Complete'
        } else {
            $script:FsrmNativeExportStatus = 'Incomplete'
            Write-Log "WARN : native FSRM XML baseline is incomplete; CSV inventory is still exported." "WARN"
        }

        # 6a. File Groups
        try {
            $fsrmGroups = Get-FsrmFileGroup -ErrorAction Stop
            $groupRows  = foreach ($g in $fsrmGroups) {
                [PSCustomObject]@{
                    Name           = $g.Name
                    IncludePattern = $g.IncludePattern -join '; '
                    ExcludePattern = $g.ExcludePattern -join '; '
                }
            }
            Export-CsvBaseline -Rows $groupRows -Path "$ExportRoot\fsrm_filegroups.csv" `
                -Columns @('Name','IncludePattern','ExcludePattern')
            Write-Log ("FSRM File Groups : {0}" -f ($fsrmGroups | Measure-Object).Count)

            $sb = New-Object System.Text.StringBuilder
            [void]$sb.AppendLine('#Requires -Modules FileServerResourceManager')
            [void]$sb.AppendLine("# Reimport FSRM File Groups - generated $(Get-Date -Format 'yyyy-MM-dd HH:mm') from $env:COMPUTERNAME")
            [void]$sb.AppendLine('')
            foreach ($g in $fsrmGroups) {
                $inc = ($g.IncludePattern | ForEach-Object { ConvertTo-PsSingleQuoted $_ }) -join ','
                $exc = ($g.ExcludePattern | ForEach-Object { ConvertTo-PsSingleQuoted $_ }) -join ','
                $nameLiteral = ConvertTo-PsSingleQuoted $g.Name
                [void]$sb.AppendLine("# $($g.Name)")
                $cmd = "New-FsrmFileGroup -Name $nameLiteral"
                if ($g.IncludePattern) { $cmd += " -IncludePattern @($inc)" }
                if ($g.ExcludePattern) { $cmd += " -ExcludePattern @($exc)" }
                [void]$sb.AppendLine($cmd)
                [void]$sb.AppendLine('')
            }
            $sb.ToString() | Out-File "$ExportRoot\fsrm_reimport_filegroups.ps1" -Encoding UTF8
        } catch {
            Write-Log "WARN : Get-FsrmFileGroup failed : $_" "WARN"
        }

        # 6b. File Screen Templates
        try {
            $fsrmTemplates = Get-FsrmFileScreenTemplate -ErrorAction Stop
            $templateRows  = foreach ($t in $fsrmTemplates) {
                [PSCustomObject]@{
                    Name         = $t.Name
                    Description  = $t.Description
                    Active       = $t.Active
                    IncludeGroup = $t.IncludeGroup -join '; '
                }
            }
            Export-CsvBaseline -Rows $templateRows -Path "$ExportRoot\fsrm_screen_templates.csv" `
                -Columns @('Name','Description','Active','IncludeGroup')
            Write-Log ("FSRM File Screen Templates : {0}" -f ($fsrmTemplates | Measure-Object).Count)

            $sb2 = New-Object System.Text.StringBuilder
            [void]$sb2.AppendLine('#Requires -Modules FileServerResourceManager')
            [void]$sb2.AppendLine("# Reimport FSRM File Screen Templates - generated $(Get-Date -Format 'yyyy-MM-dd HH:mm') from $env:COMPUTERNAME")
            [void]$sb2.AppendLine('')
            foreach ($t in $fsrmTemplates) {
                $groups = ($t.IncludeGroup | ForEach-Object { ConvertTo-PsSingleQuoted $_ }) -join ','
                $active = if ($t.Active) { '$true' } else { '$false' }
                $nameLiteral = ConvertTo-PsSingleQuoted $t.Name
                $descLiteral = ConvertTo-PsSingleQuoted $t.Description
                [void]$sb2.AppendLine("# $($t.Name)")
                $cmd = "New-FsrmFileScreenTemplate -Name $nameLiteral -Active:$active"
                if ($t.IncludeGroup) { $cmd += " -IncludeGroup @($groups)" }
                if ($t.Description)  { $cmd += " -Description $descLiteral" }
                [void]$sb2.AppendLine($cmd)
                [void]$sb2.AppendLine('')
            }
            $sb2.ToString() | Out-File "$ExportRoot\fsrm_reimport_templates.ps1" -Encoding UTF8
        } catch {
            Write-Log "WARN : Get-FsrmFileScreenTemplate failed : $_" "WARN"
        }

        # 6c. File Screens applied on paths
        try {
            $fsrmScreens = Get-FsrmFileScreen -ErrorAction Stop
            $screenRows  = foreach ($s in $fsrmScreens) {
                [PSCustomObject]@{
                    Path            = $s.Path
                    Active          = $s.Active
                    Template        = $s.Template
                    IncludeGroup    = $s.IncludeGroup -join '; '
                    MatchesTemplate = $s.MatchesTemplate
                }
            }
            Export-CsvBaseline -Rows $screenRows -Path "$ExportRoot\fsrm_screens_applied.csv" `
                -Columns @('Path','Active','Template','IncludeGroup','MatchesTemplate')
            Write-Log ("FSRM File Screens applied : {0}" -f ($fsrmScreens | Measure-Object).Count)

            $sb3 = New-Object System.Text.StringBuilder
            [void]$sb3.AppendLine('#Requires -Modules FileServerResourceManager')
            [void]$sb3.AppendLine("# Reimport FSRM File Screens - generated $(Get-Date -Format 'yyyy-MM-dd HH:mm') from $env:COMPUTERNAME")
            [void]$sb3.AppendLine('')
            foreach ($s in $fsrmScreens) {
                $active = if ($s.Active) { '$true' } else { '$false' }
                $pathLiteral = ConvertTo-PsSingleQuoted $s.Path
                [void]$sb3.AppendLine("# $($s.Path)")
                if ($s.Template -and $s.MatchesTemplate) {
                    $templateLiteral = ConvertTo-PsSingleQuoted $s.Template
                    [void]$sb3.AppendLine("New-FsrmFileScreen -Path $pathLiteral -Template $templateLiteral -Active:$active")
                } else {
                    $groups = ($s.IncludeGroup | ForEach-Object { ConvertTo-PsSingleQuoted $_ }) -join ','
                    $cmd = "New-FsrmFileScreen -Path $pathLiteral -Active:$active"
                    if ($s.IncludeGroup) { $cmd += " -IncludeGroup @($groups)" }
                    [void]$sb3.AppendLine($cmd)
                }
                [void]$sb3.AppendLine('')
            }
            $sb3.ToString() | Out-File "$ExportRoot\fsrm_reimport_screens.ps1" -Encoding UTF8
        } catch {
            Write-Log "WARN : Get-FsrmFileScreen failed : $_" "WARN"
        }

        # 6d. Quota Templates
        try {
            $fsrmQuotaTemplates = Get-FsrmQuotaTemplate -ErrorAction Stop
            $qtRows = foreach ($qt in $fsrmQuotaTemplates) {
                [PSCustomObject]@{
                    Name        = $qt.Name
                    Description = $qt.Description
                    Size        = $qt.Size
                    SoftLimit   = $qt.SoftLimit
                    Threshold   = ($qt.Threshold | ForEach-Object { "$($_.Percentage)%" }) -join '; '
                }
            }
            Export-CsvBaseline -Rows $qtRows -Path "$ExportRoot\fsrm_quota_templates.csv" `
                -Columns @('Name','Description','Size','SoftLimit','Threshold')
            Write-Log ("FSRM Quota Templates : {0}" -f ($fsrmQuotaTemplates | Measure-Object).Count)
        } catch {
            Write-Log "WARN : Get-FsrmQuotaTemplate failed : $_" "WARN"
        }

        # 6e. Quotas applied on paths
        try {
            $fsrmQuotas = Get-FsrmQuota -ErrorAction Stop
            $quotaRows  = foreach ($q in $fsrmQuotas) {
                [PSCustomObject]@{
                    Path            = $q.Path
                    Size            = $q.Size
                    SoftLimit       = $q.SoftLimit
                    Template        = $q.Template
                    Usage           = $q.Usage
                    MatchesTemplate = $q.MatchesTemplate
                }
            }
            Export-CsvBaseline -Rows $quotaRows -Path "$ExportRoot\fsrm_quotas_applied.csv" `
                -Columns @('Path','Size','SoftLimit','Template','Usage','MatchesTemplate')
            Write-Log ("FSRM Quotas applied : {0}" -f ($fsrmQuotas | Measure-Object).Count)

            $sb4 = New-Object System.Text.StringBuilder
            [void]$sb4.AppendLine('#Requires -Modules FileServerResourceManager')
            [void]$sb4.AppendLine("# Reimport FSRM Quotas - generated $(Get-Date -Format 'yyyy-MM-dd HH:mm') from $env:COMPUTERNAME")
            [void]$sb4.AppendLine('')
            foreach ($q in $fsrmQuotas) {
                $soft = if ($q.SoftLimit) { '-SoftLimit' } else { '' }
                $pathLiteral = ConvertTo-PsSingleQuoted $q.Path
                [void]$sb4.AppendLine("# $($q.Path)")
                if ($q.Template -and $q.MatchesTemplate) {
                    $templateLiteral = ConvertTo-PsSingleQuoted $q.Template
                    [void]$sb4.AppendLine(("New-FsrmQuota -Path {0} -Template {1} {2}" -f $pathLiteral, $templateLiteral, $soft).Trim())
                } else {
                    [void]$sb4.AppendLine(("New-FsrmQuota -Path {0} -Size {1} {2}" -f $pathLiteral, $q.Size, $soft).Trim())
                }
                [void]$sb4.AppendLine('')
            }
            $sb4.ToString() | Out-File "$ExportRoot\fsrm_reimport_quotas.ps1" -Encoding UTF8
        } catch {
            Write-Log "WARN : Get-FsrmQuota failed : $_" "WARN"
        }
    }
}

# ---------------------------------------------------------------------------
# Step 8 : LanmanServer registry backup
# ---------------------------------------------------------------------------
if ($run['LanmanReg']) {
    Write-Log "--- Step 8 : SMB Shares registry backup (LanmanServer) ---"
    $lanmanKey  = "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Shares"
    $lanmanFile = "$ExportRoot\registry_LanmanServer_Shares.reg"
    $lanOut = & reg.exe export $lanmanKey $lanmanFile /y 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Log "LanmanServer Shares registry exported : $lanmanFile"
    } else {
        Write-Log "ERROR : LanmanServer registry export failed : $lanOut" "ERROR"
    }
}

# ---------------------------------------------------------------------------
# Step 9 : Enterprise Vault KVS registry key
# ---------------------------------------------------------------------------
if ($run['KVS']) {
    Write-Log "--- Step 9 : Enterprise Vault KVS registry key ---"
    $kvsKey  = "HKLM\SOFTWARE\Wow6432Node\KVS"
    $kvsFile = "$ExportRoot\registry_KVS.reg"
    $regOut  = & reg.exe export $kvsKey $kvsFile /y 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Log "KVS key exported : $kvsFile"
    } else {
        Write-Log "ERROR : KVS registry export failed (key missing?) : $regOut" "ERROR"
    }
}

# ---------------------------------------------------------------------------
# Export metadata - lets Compare distinguish an intentional partial export from
# a missing/corrupted baseline artifact. Kept as one-row CSV for PS4 simplicity.
# ---------------------------------------------------------------------------
[PSCustomObject]@{
    SchemaVersion         = '2.5'
    SourceServer          = $env:COMPUTERNAME
    ExportedAt            = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    SelectedSteps         = ($runList -join ',')
    FullACLBackup         = $FullACLBackup.ToString()
    AllFolderAcls         = $AllFolderAcls.ToString()
    FolderAclDepth        = $FolderAclDepth
    InheritanceCheckDepth = $InheritanceCheckDepth
    RemoteMode            = $remoteMode.ToString()
    FsrmNativeExport      = $script:FsrmNativeExportStatus
} | Export-Csv -Path "$ExportRoot\export_metadata.csv" -NoTypeInformation -Encoding UTF8

# ---------------------------------------------------------------------------
# Integrity manifest - verified by the Compare script after the folder is copied.
# summary.txt is excluded (it keeps growing after the manifest is written).
# ---------------------------------------------------------------------------
$manifestRows = New-Object 'System.Collections.Generic.List[PSCustomObject]'
foreach ($file in (Get-ChildItem $ExportRoot -Recurse -File)) {
    if ($file.Name -eq 'manifest.csv' -or $file.Name -eq 'summary.txt') { continue }
    try {
        $h = Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256 -ErrorAction Stop
        $manifestRows.Add([PSCustomObject]@{
            RelativePath = $file.FullName.Substring($ExportRoot.Length).TrimStart('\')
            Length       = $file.Length
            SHA256       = $h.Hash
        })
    } catch {
        Write-Log "WARN : hash failed for '$($file.FullName)' : $_" "WARN"
    }
}
$manifestRows | Export-Csv -Path "$ExportRoot\manifest.csv" -NoTypeInformation -Encoding UTF8
Write-Log ("Integrity manifest : {0} files hashed (SHA256) -> manifest.csv" -f $manifestRows.Count)

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Log "=== Export complete ==="
Write-Log "Output folder contents :"
Get-ChildItem $ExportRoot | ForEach-Object {
    if ($_.PSIsContainer) {
        Write-Log ("  {0,-45}      [dir]" -f $_.Name)
    } else {
        Write-Log ("  {0,-45} {1,10} KB" -f $_.Name, [math]::Round($_.Length / 1KB, 1))
    }
}
Write-Log "Copy this folder to the new W2K22 server before running Compare-FileServer-AfterMigration.ps1"
Write-Log ("Export status : {0} warning(s), {1} error(s)" -f $script:ExportWarningCount, $script:ExportErrorCount)
if ($script:ExportErrorCount -gt 0) { exit 1 }
