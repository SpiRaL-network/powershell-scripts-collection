[CmdletBinding()]
param(
    [string]$ChildScenario = '',
    [string]$TestRoot = ''
)

$ErrorActionPreference = 'Stop'

function Get-HashHex {
    param([string]$Value)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
        return [System.BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Get-NormalizedTestDacl {
    param([string]$Sddl)
    $aceStart = $Sddl.IndexOf('(')
    if ($aceStart -lt 0) { $flags=$Sddl.Substring(2); $aces='' }
    else { $flags=$Sddl.Substring(2,$aceStart-2); $aces=$Sddl.Substring($aceStart) }
    $protection = if ($flags -match 'P') { 'P' } else { '' }
    return "D:$protection$aces"
}

function Write-TestManifest {
    param([string]$Folder)
    $rows = foreach ($file in (Get-ChildItem -LiteralPath $Folder -Recurse -File)) {
        if ($file.Name -eq 'manifest.csv' -or $file.Name -like 'report*') { continue }
        [PSCustomObject]@{
            RelativePath = $file.FullName.Substring($Folder.Length).TrimStart('\')
            Length       = $file.Length
            SHA256       = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
        }
    }
    $rows | Export-Csv -LiteralPath (Join-Path $Folder 'manifest.csv') -NoTypeInformation -Encoding UTF8
}

function Get-StrippedScriptBlock {
    param([string]$Path)
    $text = Get-Content -LiteralPath $Path -Raw
    $text = [regex]::Replace($text, '(?m)^#Requires[^\r\n]*\r?\n', '')
    return [ScriptBlock]::Create($text)
}

if ($ChildScenario -ne '') {
    $comparePath = Join-Path $PSScriptRoot 'Compare-FileServer-AfterMigration.ps1'
    $exportPath  = Join-Path $PSScriptRoot 'Export-FileServer-BeforeMigration.ps1'

    if ($ChildScenario -eq 'ExportDepth') {
        $dataRoot = Join-Path $TestRoot 'PRODTEST_Data\ShareRoot'
        $exportRoot = Join-Path $TestRoot 'PRODTEST_ExportDepth'
        $sb = Get-StrippedScriptBlock $exportPath
        & $sb -ExportRoot $exportRoot -Paths $dataRoot -Steps ACLs,Inheritance `
            -FolderAclDepth 0 -InheritanceCheckDepth -1 -ExcludeDrives 'Q:'
        exit $LASTEXITCODE
    }

    if ($ChildScenario -eq 'ExistingRoot') {
        $dataRoot = Join-Path $TestRoot 'PRODTEST_Data\ShareRoot'
        $exportRoot = Join-Path $TestRoot 'PRODTEST_ExistingRoot'
        $sb = Get-StrippedScriptBlock $exportPath
        & $sb -ExportRoot $exportRoot -Paths $dataRoot -Steps ACLs `
            -FolderAclDepth 0 -InheritanceCheckDepth 0 -ExcludeDrives 'Q:'
        exit $LASTEXITCODE
    }

    if ($ChildScenario -eq 'TaskCollision') {
        function Get-SmbShare { @() }
        function Get-ScheduledTask {
            $principal = [PSCustomObject]@{ UserId = 'PRODTEST_USER'; RunLevel = 'Limited'; LogonType = 'S4U' }
            @(
                [PSCustomObject]@{ TaskName='B_C'; TaskPath='\A\'; State='Ready'; Description=''; Principal=$principal; Actions=@([PSCustomObject]@{Execute='cmd.exe';Arguments='/c exit 0'}); Triggers=@([PSCustomObject]@{}) },
                [PSCustomObject]@{ TaskName='C'; TaskPath='\A_B\'; State='Ready'; Description=''; Principal=$principal; Actions=@([PSCustomObject]@{Execute='cmd.exe';Arguments='/c exit 0'}); Triggers=@([PSCustomObject]@{}) }
            )
        }
        function Get-ScheduledTaskInfo { [PSCustomObject]@{ NextRunTime=$null; LastRunTime=$null; LastTaskResult=0 } }
        function Export-ScheduledTask {
            param([string]$TaskName,[string]$TaskPath)
            "<Task><Name>$TaskName</Name><Path>$TaskPath</Path></Task>"
        }
        $exportRoot = Join-Path $TestRoot 'PRODTEST_TaskCollision'
        $sb = Get-StrippedScriptBlock $exportPath
        & $sb -ExportRoot $exportRoot -Steps Tasks -ExcludeDrives 'Q:'
        exit $LASTEXITCODE
    }

    if ($ChildScenario -eq 'FsrmExport') {
        function Get-Module { [CmdletBinding()] param([switch]$ListAvailable,[string]$Name) [PSCustomObject]@{Name=$Name} }
        function Import-Module { [CmdletBinding()] param([string]$Name) }
        function Get-FsrmFileGroup { [PSCustomObject]@{Name='PRODTEST_GROUP';IncludePattern=@('*.tmp');ExcludePattern=@()} }
        function Get-FsrmFileScreenTemplate { [PSCustomObject]@{Name='PRODTEST_SCREEN_TEMPLATE';Description='test';Active=$true;IncludeGroup=@('PRODTEST_GROUP')} }
        function Get-FsrmFileScreen { @() }
        function Get-FsrmQuotaTemplate { [PSCustomObject]@{Name='PRODTEST_QUOTA_TEMPLATE';Description='test';Size=[UInt64]1048576;SoftLimit=$true;Threshold=@()} }
        function Get-FsrmQuota { @() }
        function filescrn.exe {
            $fileArgument = $args | Where-Object { $_ -like '/file:*' } | Select-Object -First 1
            $outputPath = [string]$fileArgument -replace '^/file:', ''
            Set-Content -LiteralPath $outputPath -Value '<FsrmExport />' -Encoding UTF8
        }
        function dirquota.exe {
            $fileArgument = $args | Where-Object { $_ -like '/file:*' } | Select-Object -First 1
            $outputPath = [string]$fileArgument -replace '^/file:', ''
            Set-Content -LiteralPath $outputPath -Value '<FsrmExport />' -Encoding UTF8
        }
        $exportRoot = Join-Path $TestRoot 'PRODTEST_FsrmExport'
        $sb = Get-StrippedScriptBlock $exportPath
        & $sb -ExportRoot $exportRoot -Steps FSRM -ExcludeDrives 'Q:'
        exit $LASTEXITCODE
    }

    if ($ChildScenario -eq 'LocalAccountsExport') {
        function Get-CimInstance {
            [CmdletBinding()]
            param([string]$ClassName,[string]$Filter)
            if ($ClassName -eq 'Win32_UserAccount') {
                return @(
                    [PSCustomObject]@{Name='Administrator';Domain=$env:COMPUTERNAME;SID='S-1-5-21-10-20-30-500';Description='Built-in';FullName='';Disabled=$true;Lockout=$false;PasswordRequired=$true;PasswordChangeable=$true;PasswordExpires=$false;AccountType=512;Status='OK';LocalAccount=$true},
                    [PSCustomObject]@{Name='svc_migrate';Domain=$env:COMPUTERNAME;SID='S-1-5-21-10-20-30-1001';Description='Service';FullName='Migration Service';Disabled=$false;Lockout=$false;PasswordRequired=$true;PasswordChangeable=$true;PasswordExpires=$false;AccountType=512;Status='OK';LocalAccount=$true}
                )
            }
            if ($ClassName -eq 'Win32_Group') {
                return [PSCustomObject]@{Name='Administrators';Domain=$env:COMPUTERNAME;SID='S-1-5-32-544';LocalAccount=$true}
            }
            return @()
        }
        function Get-CimAssociatedInstance {
            [CmdletBinding()]
            param($InputObject,[string]$Association)
            return @(
                [PSCustomObject]@{Name='Administrator';Domain=$env:COMPUTERNAME;SID='S-1-5-21-10-20-30-500';SIDType=1;LocalAccount=$true},
                [PSCustomObject]@{Name='FileAdmins';Domain='CUSTOM';SID='S-1-5-21-40-50-60-2001';SIDType=2;LocalAccount=$false}
            )
        }
        $exportRoot = Join-Path $TestRoot 'PRODTEST_LocalAccountsExport'
        $sb = Get-StrippedScriptBlock $exportPath
        & $sb -ExportRoot $exportRoot -Steps LocalAccounts -ExcludeDrives 'Q:'
        exit $LASTEXITCODE
    }

    $baseline = Join-Path $TestRoot ("PRODTEST_Baseline_{0}" -f $ChildScenario)
    $script:NewShareCalled = $false
    $global:PRODTEST_SCENARIO = $ChildScenario

    function Get-SmbShare {
        [CmdletBinding()]
        param([string]$Name)
        if ((Split-Path $baseline -Leaf) -eq 'PRODTEST_Baseline_CorruptFix') { return @() }
        $row = Import-Csv (Join-Path $baseline 'shares.csv') | Select-Object -First 1
        [PSCustomObject]@{
            Name=$row.Name; Path=$row.Path
            Description=$(if ((Split-Path $baseline -Leaf) -eq 'PRODTEST_Baseline_AdminDescription') { 'English automatic description' } else { $row.Description })
            ScopeName=$row.ScopeName
            CachingMode=$row.CachingMode
            EncryptData=$(if ((Split-Path $baseline -Leaf) -eq 'PRODTEST_Baseline_ShareDrift') { $true } else { [bool]::Parse($row.EncryptData) })
            FolderEnumerationMode=$row.FolderEnumerationMode
            ConcurrentUserLimit=[int]$row.ConcurrentUserLimit
            ContinuouslyAvailable=[bool]::Parse($row.ContinuouslyAvailable)
            Special=$false
        }
    }
    function Get-SmbShareAccess {
        [CmdletBinding()]
        param([string]$Name)
        $rows = @(Import-Csv (Join-Path $baseline 'shares_permissions.csv'))
        $result = @(foreach ($row in $rows) {
            $currentAccount = if ((Split-Path $baseline -Leaf) -eq 'PRODTEST_Baseline_CrossLocale') { 'Everyone' } else { $row.AccountName }
            [PSCustomObject]@{ AccountName=$currentAccount; AccessControlType=$row.AccessControlType; AccessRight=$row.AccessRight }
        })
        if ((Split-Path $baseline -Leaf) -eq 'PRODTEST_Baseline_ExtraPerm') {
            $result += [PSCustomObject]@{ AccountName='PRODTEST_EXTRA'; AccessControlType='Allow'; AccessRight='Full' }
        }
        return $result
    }
    function New-SmbShare {
        [CmdletBinding()]
        param([string]$Name,[string]$Path,[string]$Description,[string]$ScopeName,[string]$CachingMode,
              [bool]$EncryptData,[string]$FolderEnumerationMode,[int]$ConcurrentUserLimit,
              [bool]$ContinuouslyAvailable)
        $script:NewShareCalled = $true
        Set-Content -LiteralPath (Join-Path $TestRoot 'PRODTEST_NewShareCalled.txt') -Value $Name
        [PSCustomObject]@{ Name=$Name; Path=$Path }
    }
    function Grant-SmbShareAccess { [CmdletBinding()] param([string]$Name,[string]$AccountName,[string]$AccessRight,[switch]$Force) }
    function Block-SmbShareAccess { [CmdletBinding()] param([string]$Name,[string]$AccountName,[switch]$Force) }

    if ($ChildScenario -eq 'VolumeStable' -or $ChildScenario -eq 'VolumeLetterDrift') {
        function Get-Volume {
            $letter = if ($ChildScenario -eq 'VolumeLetterDrift') { 'F' } else { 'E' }
            [PSCustomObject]@{
                DriveLetter=$letter;FileSystemLabel='PRODTEST_DATA';FileSystem='NTFS';DriveType='Fixed'
                HealthStatus='Healthy';OperationalStatus=@('OK');SizeRemaining=[UInt64]53687091200
                Size=[UInt64]107374182400;UniqueId='VOL-PRODTEST-001';Path='VOL-PRODTEST-001'
            }
        }
        function Get-Partition {
            $letter = if ($ChildScenario -eq 'VolumeLetterDrift') { 'F' } else { 'E' }
            [PSCustomObject]@{
                DriveLetter=$letter;AccessPaths=@('VOL-PRODTEST-001');DiskNumber=7;PartitionNumber=1
                Guid='PART-PRODTEST-001';Offset=[UInt64]1048576;Size=[UInt64]107374182400;Type='Basic'
            }
        }
        function Get-Disk {
            [PSCustomObject]@{
                Number=7;FriendlyName='PRODTEST Disk';SerialNumber='SERIAL-PRODTEST-001'
                UniqueId='DISK-PRODTEST-001';Guid='GUID-PRODTEST-001';Signature=0
                PartitionStyle='GPT';OperationalStatus=@('Online');HealthStatus='Healthy'
                Size=[UInt64]107375230976;BusType='SAS';IsBoot=$false;IsSystem=$false
                IsOffline=$false;IsReadOnly=$false;Location='PRODTEST Bay'
            }
        }
    }

    if ($ChildScenario -eq 'LocalAccountsClean' -or $ChildScenario -eq 'LocalAdminExtra') {
        function Get-CimInstance {
            [CmdletBinding()]
            param([string]$ClassName,[string]$Filter)
            if ($ClassName -eq 'Win32_UserAccount') {
                return @(
                    [PSCustomObject]@{Name='Administrator';Domain=$env:COMPUTERNAME;SID='S-1-5-21-70-80-90-500';Description='Built-in';FullName='';Disabled=$true;Lockout=$false;PasswordRequired=$true;PasswordChangeable=$true;PasswordExpires=$false;LocalAccount=$true},
                    [PSCustomObject]@{Name='svc_migrate';Domain=$env:COMPUTERNAME;SID='S-1-5-21-70-80-90-1001';Description='Service';FullName='Migration Service';Disabled=$false;Lockout=$false;PasswordRequired=$true;PasswordChangeable=$true;PasswordExpires=$false;LocalAccount=$true}
                )
            }
            if ($ClassName -eq 'Win32_Group') {
                return [PSCustomObject]@{Name='Administrators';Domain=$env:COMPUTERNAME;SID='S-1-5-32-544';LocalAccount=$true}
            }
            return @()
        }
        function Get-CimAssociatedInstance {
            [CmdletBinding()]
            param($InputObject,[string]$Association)
            $members = @(
                [PSCustomObject]@{Name='Administrator';Domain=$env:COMPUTERNAME;SID='S-1-5-21-70-80-90-500';SIDType=1;LocalAccount=$true},
                [PSCustomObject]@{Name='FileAdmins';Domain='CUSTOM';SID='S-1-5-21-40-50-60-2001';SIDType=2;LocalAccount=$false}
            )
            if ($ChildScenario -eq 'LocalAdminExtra') {
                $members += [PSCustomObject]@{Name='UnexpectedAdmin';Domain='CUSTOM';SID='S-1-5-21-40-50-60-2999';SIDType=1;LocalAccount=$false}
            }
            return $members
        }
    }

    if ($ChildScenario -eq 'TaskFixBlocked' -or $ChildScenario -eq 'TaskFilteredFix' -or
        $ChildScenario -eq 'TaskAllEligible' -or $ChildScenario -eq 'TaskBadPattern') {
        $script:PRODTEST_Tasks = @{}
        function Get-ScheduledTask {
            [CmdletBinding()]
            param([string]$TaskName,[string]$TaskPath)
            if (-not [string]::IsNullOrWhiteSpace($TaskName)) {
                return $script:PRODTEST_Tasks["$TaskPath$TaskName"]
            }
            return @($script:PRODTEST_Tasks.Values)
        }
        function Register-ScheduledTask {
            [CmdletBinding()]
            param([string]$TaskName,[string]$TaskPath,[string]$Xml,[switch]$Force)
            $task = [PSCustomObject]@{
                TaskName=$TaskName;TaskPath=$TaskPath;State='Ready'
                Principal=[PSCustomObject]@{UserId='SYSTEM';RunLevel='Limited';LogonType='ServiceAccount'}
                Actions=@([PSCustomObject]@{Execute='cmd.exe';Arguments='/c exit 0'})
                Triggers=@((New-Object Object))
            }
            $script:PRODTEST_Tasks["$TaskPath$TaskName"] = $task
            $taskMarkerName = "PRODTEST_TasksRegistered_{0}.txt" -f $ChildScenario
            Add-Content -LiteralPath (Join-Path $TestRoot $taskMarkerName) -Value "$TaskPath$TaskName"
            return $task
        }
    }

    if ($ChildScenario -eq 'FsrmFix' -or $ChildScenario -eq 'FsrmLocalized' -or
        $ChildScenario -eq 'FsrmNativeFix' -or $ChildScenario -eq 'FsrmVerifyFail') {
        $script:PRODTEST_FsrmGroups = @{}
        $script:PRODTEST_FsrmScreenTemplates = @{}
        $script:PRODTEST_FsrmQuotaTemplates = @{}
        $script:PRODTEST_FsrmScreens = @{}
        $script:PRODTEST_FsrmQuotas = @{}
        if ($ChildScenario -eq 'FsrmLocalized') {
            $localizedDataRoot = (Import-Csv (Join-Path $baseline 'shares.csv') | Select-Object -First 1).Path
            foreach ($englishGroupName in @('Audio and Video Files','Backup Files','Compressed Files','E-mail Files',
                    'Executable Files','Image Files','Office Files','System Files','Temporary Files','Text Files','Web Page Files')) {
                $script:PRODTEST_FsrmGroups[$englishGroupName] = [PSCustomObject]@{Name=$englishGroupName;IncludePattern=@('*.server2022');ExcludePattern=@()}
            }
            $screenDefinitions = @(
                [PSCustomObject]@{Name='Block Audio and Video Files';Groups=@('Audio and Video Files');Active=$true},
                [PSCustomObject]@{Name='Block E-mail Files';Groups=@('E-mail Files');Active=$true},
                [PSCustomObject]@{Name='Block Executable Files';Groups=@('Executable Files');Active=$true},
                [PSCustomObject]@{Name='Block Image Files';Groups=@('Image Files');Active=$true},
                [PSCustomObject]@{Name='Monitor Executable and System Files';Groups=@('Executable Files','System Files');Active=$false}
            )
            foreach ($screenDefinition in $screenDefinitions) {
                $script:PRODTEST_FsrmScreenTemplates[$screenDefinition.Name] = [PSCustomObject]@{
                    Name=$screenDefinition.Name;Description='English';IncludeGroup=$screenDefinition.Groups;Active=$screenDefinition.Active
                }
            }
            $script:PRODTEST_FsrmQuotaTemplates['100 MB Limit'] = [PSCustomObject]@{Name='100 MB Limit';Description='English';Size=[UInt64]104857600;SoftLimit=$false;Threshold=@([PSCustomObject]@{Percentage=85},[PSCustomObject]@{Percentage=100})}
            $script:PRODTEST_FsrmQuotaTemplates['200 MB Limit Reports to User'] = [PSCustomObject]@{Name='200 MB Limit Reports to User';Description='English A';Size=[UInt64]209715200;SoftLimit=$false;Threshold=@([PSCustomObject]@{Percentage=85},[PSCustomObject]@{Percentage=100})}
            $script:PRODTEST_FsrmQuotaTemplates['200 MB Limit with 50 MB Extension'] = [PSCustomObject]@{Name='200 MB Limit with 50 MB Extension';Description='English B';Size=[UInt64]209715200;SoftLimit=$false;Threshold=@([PSCustomObject]@{Percentage=85},[PSCustomObject]@{Percentage=100})}
            $script:PRODTEST_FsrmScreens[$localizedDataRoot] = [PSCustomObject]@{Path=$localizedDataRoot;Active=$true;Template='Block Audio and Video Files';IncludeGroup=@('Audio and Video Files')}
            $script:PRODTEST_FsrmQuotas[$localizedDataRoot] = [PSCustomObject]@{Path=$localizedDataRoot;Size=[UInt64]104857600;SoftLimit=$false;Template='100 MB Limit'}
        } elseif ($ChildScenario -eq 'FsrmNativeFix') {
            $nativeDataRoot = (Import-Csv (Join-Path $baseline 'shares.csv') | Select-Object -First 1).Path
            $script:PRODTEST_FsrmScreens[$nativeDataRoot] = [PSCustomObject]@{Path=$nativeDataRoot;Active=$true;Template='PRODTEST_SCREEN_TEMPLATE';IncludeGroup=@('PRODTEST_GROUP')}
            $script:PRODTEST_FsrmQuotas[$nativeDataRoot] = [PSCustomObject]@{Path=$nativeDataRoot;Size=[UInt64]1048576;SoftLimit=$true;Template='PRODTEST_QUOTA_TEMPLATE'}
        }
        function Get-Module { [CmdletBinding()] param([switch]$ListAvailable,[string]$Name) [PSCustomObject]@{Name=$Name} }
        function Import-Module { [CmdletBinding()] param([string]$Name) }
        function Get-FsrmFileGroup { [CmdletBinding()] param([string]$Name) if($Name){return $script:PRODTEST_FsrmGroups[$Name]} return @($script:PRODTEST_FsrmGroups.Values) }
        function New-FsrmFileGroup { [CmdletBinding()] param([string]$Name,[string[]]$IncludePattern,[string[]]$ExcludePattern) if($ChildScenario -eq 'FsrmVerifyFail'){$IncludePattern=@('*.wrong')};$script:PRODTEST_FsrmGroups[$Name]=[PSCustomObject]@{Name=$Name;IncludePattern=$IncludePattern;ExcludePattern=$ExcludePattern} }
        function Set-FsrmFileGroup { [CmdletBinding()] param([string]$Name,[string[]]$IncludePattern,[string[]]$ExcludePattern) $script:PRODTEST_FsrmGroups[$Name]=[PSCustomObject]@{Name=$Name;IncludePattern=$IncludePattern;ExcludePattern=$ExcludePattern} }
        function Get-FsrmFileScreenTemplate { [CmdletBinding()] param([string]$Name) if($Name){return $script:PRODTEST_FsrmScreenTemplates[$Name]} return @($script:PRODTEST_FsrmScreenTemplates.Values) }
        function New-FsrmFileScreenTemplate { [CmdletBinding()] param([string]$Name,[string]$Description,[string[]]$IncludeGroup,[switch]$Active) $script:PRODTEST_FsrmScreenTemplates[$Name]=[PSCustomObject]@{Name=$Name;Description=$Description;IncludeGroup=$IncludeGroup;Active=$Active.IsPresent} }
        function Set-FsrmFileScreenTemplate { [CmdletBinding()] param([string]$Name,[string]$Description,[string[]]$IncludeGroup,[switch]$Active) $script:PRODTEST_FsrmScreenTemplates[$Name]=[PSCustomObject]@{Name=$Name;Description=$Description;IncludeGroup=$IncludeGroup;Active=$Active.IsPresent} }
        function New-FsrmQuotaThreshold { [CmdletBinding()] param([UInt32]$Percentage) [PSCustomObject]@{Percentage=$Percentage} }
        function Get-FsrmQuotaTemplate { [CmdletBinding()] param([string]$Name) if($Name){return $script:PRODTEST_FsrmQuotaTemplates[$Name]} return @($script:PRODTEST_FsrmQuotaTemplates.Values) }
        function New-FsrmQuotaTemplate { [CmdletBinding()] param([string]$Name,[string]$Description,[UInt64]$Size,[switch]$SoftLimit,$Threshold) $script:PRODTEST_FsrmQuotaTemplates[$Name]=[PSCustomObject]@{Name=$Name;Description=$Description;Size=$Size;SoftLimit=$SoftLimit.IsPresent;Threshold=@($Threshold)} }
        function Set-FsrmQuotaTemplate { [CmdletBinding()] param([string]$Name,[string]$Description,[UInt64]$Size,[switch]$SoftLimit,$Threshold) $existing=$script:PRODTEST_FsrmQuotaTemplates[$Name];$script:PRODTEST_FsrmQuotaTemplates[$Name]=[PSCustomObject]@{Name=$Name;Description=$Description;Size=$Size;SoftLimit=$SoftLimit.IsPresent;Threshold=@($existing.Threshold)} }
        function Get-FsrmFileScreen { [CmdletBinding()] param([string]$Path) if($Path){return $script:PRODTEST_FsrmScreens[$Path]} return @($script:PRODTEST_FsrmScreens.Values) }
        function New-FsrmFileScreen { [CmdletBinding()] param([string]$Path,[string]$Template,[string[]]$IncludeGroup,[switch]$Active) if($Template){$IncludeGroup=@($script:PRODTEST_FsrmScreenTemplates[$Template].IncludeGroup)};$script:PRODTEST_FsrmScreens[$Path]=[PSCustomObject]@{Path=$Path;Template=$Template;IncludeGroup=$IncludeGroup;Active=$Active.IsPresent};Add-Content -LiteralPath (Join-Path $TestRoot ("PRODTEST_FsrmCreated_{0}.txt" -f $ChildScenario)) -Value "Screen:$Path" }
        function Set-FsrmFileScreen { [CmdletBinding()] param([string]$Path,[string[]]$IncludeGroup,[switch]$Active) $existing=$script:PRODTEST_FsrmScreens[$Path];$script:PRODTEST_FsrmScreens[$Path]=[PSCustomObject]@{Path=$Path;Template=$existing.Template;IncludeGroup=$IncludeGroup;Active=$Active.IsPresent} }
        function Get-FsrmQuota { [CmdletBinding()] param([string]$Path) if($Path){return $script:PRODTEST_FsrmQuotas[$Path]} return @($script:PRODTEST_FsrmQuotas.Values) }
        function New-FsrmQuota { [CmdletBinding()] param([string]$Path,[string]$Template,[UInt64]$Size,[switch]$SoftLimit) if($Template){$Size=[UInt64]$script:PRODTEST_FsrmQuotaTemplates[$Template].Size};$script:PRODTEST_FsrmQuotas[$Path]=[PSCustomObject]@{Path=$Path;Template=$Template;Size=$Size;SoftLimit=$SoftLimit.IsPresent};Add-Content -LiteralPath (Join-Path $TestRoot ("PRODTEST_FsrmCreated_{0}.txt" -f $ChildScenario)) -Value "Quota:$Path" }
        function Set-FsrmQuota { [CmdletBinding()] param([string]$Path,[UInt64]$Size,[switch]$SoftLimit) $existing=$script:PRODTEST_FsrmQuotas[$Path];$script:PRODTEST_FsrmQuotas[$Path]=[PSCustomObject]@{Path=$Path;Template=$existing.Template;Size=$Size;SoftLimit=$SoftLimit.IsPresent} }
        if ($ChildScenario -eq 'FsrmNativeFix') {
            function filescrn.exe {
                Add-Content -LiteralPath (Join-Path $TestRoot 'PRODTEST_FsrmNativeImports.txt') -Value ($args -join '|')
                if ($args[0] -eq 'filegroup') {
                    $script:PRODTEST_FsrmGroups['PRODTEST_GROUP'] = [PSCustomObject]@{Name='PRODTEST_GROUP';IncludePattern=@('*.tmp','*.bak');ExcludePattern=@('keep.tmp')}
                } elseif ($args[0] -eq 'template') {
                    $script:PRODTEST_FsrmScreenTemplates['PRODTEST_SCREEN_TEMPLATE'] = [PSCustomObject]@{Name='PRODTEST_SCREEN_TEMPLATE';Description='test';IncludeGroup=@('PRODTEST_GROUP');Active=$true}
                }
            }
            function dirquota.exe {
                Add-Content -LiteralPath (Join-Path $TestRoot 'PRODTEST_FsrmNativeImports.txt') -Value ($args -join '|')
                $script:PRODTEST_FsrmQuotaTemplates['PRODTEST_QUOTA_TEMPLATE'] = [PSCustomObject]@{Name='PRODTEST_QUOTA_TEMPLATE';Description='test';Size=[UInt64]1048576;SoftLimit=$true;Threshold=@([PSCustomObject]@{Percentage=85},[PSCustomObject]@{Percentage=100})}
            }
            function Reset-FsrmFileScreen { [CmdletBinding()] param([string]$Path,[string]$Template) $templateObject=$script:PRODTEST_FsrmScreenTemplates[$Template];$script:PRODTEST_FsrmScreens[$Path]=[PSCustomObject]@{Path=$Path;Template=$Template;IncludeGroup=@($templateObject.IncludeGroup);Active=[bool]$templateObject.Active};Add-Content -LiteralPath (Join-Path $TestRoot 'PRODTEST_FsrmNativeResets.txt') -Value "Screen:$Path" }
            function Reset-FsrmQuota { [CmdletBinding()] param([string]$Path,[string]$Template) $templateObject=$script:PRODTEST_FsrmQuotaTemplates[$Template];$script:PRODTEST_FsrmQuotas[$Path]=[PSCustomObject]@{Path=$Path;Template=$Template;Size=[UInt64]$templateObject.Size;SoftLimit=[bool]$templateObject.SoftLimit};Add-Content -LiteralPath (Join-Path $TestRoot 'PRODTEST_FsrmNativeResets.txt') -Value "Quota:$Path" }
        }
    }

    $checks = @('Manifest','Shares','SharePerms','RootACLs','FolderACLs','Inheritance')
    $invoke = @{ ExportFolder=$baseline; Checks=$checks; ReportPath=(Join-Path $baseline 'report.html') }
    if ($ChildScenario -eq 'CorruptFix') {
        $invoke['Checks'] = @('Shares')
        $invoke['Fix'] = @('Shares')
    } elseif ($ChildScenario -eq 'MissingBaseline') {
        $invoke['Checks'] = @('Manifest','SharePerms')
    } elseif ($ChildScenario -eq 'FolderFix') {
        $invoke['Checks'] = @('Manifest','FolderACLs')
        $invoke['Fix'] = @('FolderAcls')
    } elseif ($ChildScenario -eq 'ProviderPath') {
        New-PSDrive -Name PRODTESTBASE -PSProvider FileSystem -Root $baseline | Out-Null
        $invoke['ExportFolder'] = 'PRODTESTBASE:\'
    } elseif ($ChildScenario -eq 'ManifestOnly') {
        $invoke['Checks'] = @('Manifest')
    } elseif ($ChildScenario -eq 'TaskFixBlocked') {
        $invoke['Checks'] = @('Manifest','Tasks')
        $invoke['Fix'] = @('Tasks')
    } elseif ($ChildScenario -eq 'TaskFilteredFix') {
        $invoke['Checks'] = @('Manifest','Tasks')
        $invoke['Fix'] = @('Tasks')
        $invoke['TaskInclude'] = @('CUSTOM\*','Start_Windows_Update')
    } elseif ($ChildScenario -eq 'TaskAllEligible') {
        $invoke['Checks'] = @('Manifest','Tasks')
        $invoke['Fix'] = @('Tasks')
        $invoke['AllEligibleTasks'] = $true
    } elseif ($ChildScenario -eq 'TaskBadPattern') {
        $invoke['Checks'] = @('Manifest','Tasks')
        $invoke['Fix'] = @('Tasks')
        $invoke['TaskInclude'] = @('\Start_Windows_Update\*')
    } elseif ($ChildScenario -eq 'FsrmFix') {
        $invoke['Checks'] = @('Manifest','FSRM')
        $invoke['Fix'] = @('Fsrm')
    } elseif ($ChildScenario -eq 'FsrmLocalized') {
        $invoke['Checks'] = @('Manifest','FSRM')
    } elseif ($ChildScenario -eq 'FsrmNativeFix') {
        $invoke['Checks'] = @('Manifest','FSRM')
        $invoke['Fix'] = @('Fsrm')
    } elseif ($ChildScenario -eq 'FsrmVerifyFail') {
        $invoke['Checks'] = @('Manifest','FSRM')
        $invoke['Fix'] = @('Fsrm')
    } elseif ($ChildScenario -eq 'VolumeStable' -or $ChildScenario -eq 'VolumeLetterDrift') {
        $invoke['Checks'] = @('Manifest','Volumes')
    } elseif ($ChildScenario -eq 'LocalAccountsClean' -or $ChildScenario -eq 'LocalAdminExtra') {
        $invoke['Checks'] = @('Manifest','LocalAccounts')
    }
    $sb = Get-StrippedScriptBlock $comparePath
    & $sb @invoke
    exit $LASTEXITCODE
}

$workspace = [System.IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\') + '\'
$runtime = Join-Path $PSScriptRoot 'PRODTEST_Runtime'
$runtimeFull = [System.IO.Path]::GetFullPath($runtime)
if (-not $runtimeFull.StartsWith($workspace, [StringComparison]::OrdinalIgnoreCase) -or
    (Split-Path $runtimeFull -Leaf) -notlike 'PRODTEST*') {
    throw "Unsafe test runtime path : $runtimeFull"
}

$failures = New-Object 'System.Collections.Generic.List[string]'
try {
    if (Test-Path -LiteralPath $runtimeFull) { Remove-Item -LiteralPath $runtimeFull -Recurse -Force }
    New-Item -ItemType Directory -Path $runtimeFull | Out-Null

    $dataRoot = Join-Path $runtimeFull 'PRODTEST_Data\ShareRoot'
    New-Item -ItemType Directory -Path $dataRoot -Force | Out-Null
    $current = $dataRoot
    $allDirs = New-Object 'System.Collections.Generic.List[string]'
    [void]$allDirs.Add($current)
    for ($i=1; $i -le 7; $i++) {
        $current = Join-Path $current ("Level{0}" -f $i)
        New-Item -ItemType Directory -Path $current | Out-Null
        [void]$allDirs.Add($current)
    }

    $clean = Join-Path $runtimeFull 'PRODTEST_Baseline_Clean'
    New-Item -ItemType Directory -Path $clean | Out-Null
    [PSCustomObject]@{
        Name='PRODTEST_SHARE'; Path=$dataRoot; Description='PRODTEST'; ScopeName='*'
        CurrentUsers=0; MaximumAllowed=0; CachingMode='Manual'; EncryptData=$false
        FolderEnumerationMode='Unrestricted'; ConcurrentUserLimit=0
        ContinuouslyAvailable=$false; ShareType='FileSystemDirectory'; Special=$false
    } | Export-Csv (Join-Path $clean 'shares.csv') -NoTypeInformation -Encoding UTF8
    [PSCustomObject]@{
        ShareName='PRODTEST_SHARE'; SharePath=$dataRoot; AccountName='PRODTEST_USER'
        AccessControlType='Allow'; AccessRight='Read'
    } | Export-Csv (Join-Path $clean 'shares_permissions.csv') -NoTypeInformation -Encoding UTF8

    $rootAcl = Get-Acl -LiteralPath $dataRoot
    $rootRows = foreach ($ace in $rootAcl.Access) {
        [PSCustomObject]@{
            ShareName='PRODTEST_SHARE'; Path=$dataRoot; IdentityReference=$ace.IdentityReference
            FileSystemRights=$ace.FileSystemRights; AccessControlType=$ace.AccessControlType
            IsInherited=$ace.IsInherited; InheritanceFlags=$ace.InheritanceFlags
            PropagationFlags=$ace.PropagationFlags; Owner=$rootAcl.Owner; Group=$rootAcl.Group
            AreAccessRulesProtected=$rootAcl.AreAccessRulesProtected
        }
    }
    $rootRows | Export-Csv (Join-Path $clean 'acls_roots.csv') -NoTypeInformation -Encoding UTF8

    $rootSec = (New-Object System.IO.DirectoryInfo($dataRoot)).GetAccessControl('Access, Owner')
    $rootSddl = $rootSec.GetSecurityDescriptorSddlForm('Access, Owner')
    [PSCustomObject]@{
        ShareName='PRODTEST_SHARE'; ShareRoot=$dataRoot; Path=$dataRoot; Owner=$rootAcl.Owner
        Sddl=$rootSddl; Protected=$rootSec.AreAccessRulesProtected
        ExplicitACEs=$rootSec.GetAccessRules($true,$false,[System.Security.Principal.SecurityIdentifier]).Count
    } | Export-Csv (Join-Path $clean 'acls_folders_PRODTEST_SHARE.csv') -NoTypeInformation -Encoding UTF8

    $inheritanceRows = for ($depth=0; $depth -lt $allDirs.Count; $depth++) {
        $di = New-Object System.IO.DirectoryInfo($allDirs[$depth])
        $sec = $di.GetAccessControl('Access, Owner')
        $explicit = 0; $inherited = 0
        foreach ($rule in $sec.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier])) {
            if ($rule.IsInherited) { $inherited++ } else { $explicit++ }
        }
        $owner = $sec.GetOwner([System.Security.Principal.NTAccount]).Value
        [PSCustomObject]@{
            ShareRoot=$dataRoot; Path=$allDirs[$depth]; Depth=$depth
            InheritanceEnabled=(-not $sec.AreAccessRulesProtected)
            BrokenInheritance=$sec.AreAccessRulesProtected
            ExplicitACECount=$explicit; InheritedACECount=$inherited; Owner=$owner
            DaclSha256=(Get-HashHex (Get-NormalizedTestDacl $sec.GetSecurityDescriptorSddlForm('Access')))
        }
    }
    $inheritanceRows | Export-Csv (Join-Path $clean 'inheritance_map.csv') -NoTypeInformation -Encoding UTF8
    [PSCustomObject]@{ SchemaVersion='2.3'; SelectedSteps='Shares,ACLs,Inheritance'; FullACLBackup='False'; FolderAclDepth=5; InheritanceCheckDepth=5 } |
        Export-Csv (Join-Path $clean 'export_metadata.csv') -NoTypeInformation -Encoding UTF8
    Write-TestManifest $clean

    foreach ($scenario in @('ExtraPerm','DaclDrift','MissingBaseline','CorruptFix','ShareDrift','RootAceExtra','FolderFix','CrossLocale','ProviderPath','ManifestOnly','TaskFixBlocked','TaskFilteredFix','TaskAllEligible','TaskBadPattern','FsrmFix','FsrmLocalized','FsrmNativeFix','FsrmVerifyFail','AdminDescription','SystemAclSkip','VolumeStable','VolumeLetterDrift','LocalAccountsClean','LocalAdminExtra')) {
        $target = Join-Path $runtimeFull ("PRODTEST_Baseline_{0}" -f $scenario)
        Copy-Item -LiteralPath $clean -Destination $target -Recurse
    }

    foreach ($volumeScenario in @('VolumeStable','VolumeLetterDrift')) {
        $volumeFolder = Join-Path $runtimeFull ("PRODTEST_Baseline_{0}" -f $volumeScenario)
        [PSCustomObject]@{
            DriveLetter='E';FileSystemLabel='PRODTEST_DATA';FileSystem='NTFS';DriveType='Fixed'
            HealthStatus='Healthy';OperationalStatus='OK';SizeRemaining='53687091200';Size='107374182400'
            IsDataDisk='True';VolumeUniqueId='VOL-PRODTEST-001';VolumePath='VOL-PRODTEST-001'
            DiskNumber='2';PartitionNumber='1';PartitionGuid='PART-PRODTEST-001'
            PartitionOffset='1048576';PartitionSize='107374182400';PartitionType='Basic'
            DiskUniqueId='DISK-PRODTEST-001';DiskSerialNumber='SERIAL-PRODTEST-001'
            DiskGuid='GUID-PRODTEST-001';DiskSignature='0';DiskFriendlyName='PRODTEST Disk'
            DiskBusType='SAS';DiskSize='107375230976';DiskPartitionStyle='GPT'
        } | Export-Csv (Join-Path $volumeFolder 'volumes.csv') -NoTypeInformation -Encoding UTF8
        [PSCustomObject]@{
            Number='2';FriendlyName='PRODTEST Disk';SerialNumber='SERIAL-PRODTEST-001'
            UniqueId='DISK-PRODTEST-001';Guid='GUID-PRODTEST-001';Signature='0';PartitionStyle='GPT'
            OperationalStatus='Online';HealthStatus='Healthy';Size='107375230976';BusType='SAS'
            IsBoot='False';IsSystem='False';IsOffline='False';IsReadOnly='False';Location='Source Bay'
        } | Export-Csv (Join-Path $volumeFolder 'disks.csv') -NoTypeInformation -Encoding UTF8
        [PSCustomObject]@{SchemaVersion='2.5';SelectedSteps='Volumes'} |
            Export-Csv (Join-Path $volumeFolder 'export_metadata.csv') -NoTypeInformation -Encoding UTF8
        Write-TestManifest $volumeFolder
    }

    foreach ($localScenario in @('LocalAccountsClean','LocalAdminExtra')) {
        $localFolder = Join-Path $runtimeFull ("PRODTEST_Baseline_{0}" -f $localScenario)
        @(
            [PSCustomObject]@{Name='Administrator';Domain='SOURCE';SID='S-1-5-21-10-20-30-500';Description='Built-in';FullName='';Disabled='True';Lockout='False';PasswordRequired='True';PasswordChangeable='True';PasswordExpires='False';AccountType='512';Status='OK'},
            [PSCustomObject]@{Name='svc_migrate';Domain='SOURCE';SID='S-1-5-21-10-20-30-1001';Description='Service';FullName='Migration Service';Disabled='False';Lockout='False';PasswordRequired='True';PasswordChangeable='True';PasswordExpires='False';AccountType='512';Status='OK'}
        ) | Export-Csv (Join-Path $localFolder 'local_users.csv') -NoTypeInformation -Encoding UTF8
        @(
            [PSCustomObject]@{GroupName='Administrators';GroupSID='S-1-5-32-544';AccountName='SOURCE\Administrator';Domain='SOURCE';Name='Administrator';SID='S-1-5-21-10-20-30-500';SIDType='1';IsLocal='True'},
            [PSCustomObject]@{GroupName='Administrators';GroupSID='S-1-5-32-544';AccountName='CUSTOM\FileAdmins';Domain='CUSTOM';Name='FileAdmins';SID='S-1-5-21-40-50-60-2001';SIDType='2';IsLocal='False'}
        ) | Export-Csv (Join-Path $localFolder 'local_administrators_members.csv') -NoTypeInformation -Encoding UTF8
        [PSCustomObject]@{SchemaVersion='2.5';SelectedSteps='LocalAccounts'} |
            Export-Csv (Join-Path $localFolder 'export_metadata.csv') -NoTypeInformation -Encoding UTF8
        Write-TestManifest $localFolder
    }

    foreach ($taskScenario in @('TaskFixBlocked','TaskFilteredFix','TaskAllEligible','TaskBadPattern')) {
        $taskFolder = Join-Path $runtimeFull ("PRODTEST_Baseline_{0}" -f $taskScenario)
        $taskXmlDir = Join-Path $taskFolder 'scheduled_tasks'
        New-Item -ItemType Directory -Path $taskXmlDir -Force | Out-Null
        $legacyFrenchSystem = 'Syst' + [char]0x00E8 + 'me'
        @(
            [PSCustomObject]@{TaskName='PRODTEST_CUSTOM';TaskPath='\CUSTOM\';State='Ready';Author=$legacyFrenchSystem;RunLevel='Limited';LogonType='ServiceAccount';Actions='cmd.exe /c exit 0';Triggers='Object';TaskXmlFile='custom.xml'},
            [PSCustomObject]@{TaskName='Start_Windows_Update';TaskPath='\';State='Ready';Author=$legacyFrenchSystem;RunLevel='Limited';LogonType='ServiceAccount';Actions='cmd.exe /c exit 0';Triggers='Object';TaskXmlFile='start.xml'},
            [PSCustomObject]@{TaskName='SqmUpload_S-1-5-21-1';TaskPath='\WPD\';State='Ready';Author=$legacyFrenchSystem;RunLevel='Limited';LogonType='ServiceAccount';Actions='cmd.exe /c exit 0';Triggers='Object';TaskXmlFile='wpd.xml'},
            [PSCustomObject]@{TaskName='PRODTEST_OS_TASK';TaskPath='\Microsoft\Windows\PRODTEST\';State='Ready';Author=$legacyFrenchSystem;RunLevel='Limited';LogonType='ServiceAccount';Actions='cmd.exe /c exit 0';Triggers='Object';TaskXmlFile='microsoft.xml'},
            [PSCustomObject]@{TaskName='azcmagent';TaskPath='\';State='Ready';Author=$legacyFrenchSystem;RunLevel='Limited';LogonType='ServiceAccount';Actions='cmd.exe /c exit 0';Triggers='Object';TaskXmlFile='azcmagent.xml'}
        ) | Export-Csv (Join-Path $taskFolder 'scheduled_tasks.csv') -NoTypeInformation -Encoding UTF8
        '<Task></Task>' | Out-File (Join-Path $taskXmlDir 'custom.xml') -Encoding UTF8
        '<Task></Task>' | Out-File (Join-Path $taskXmlDir 'start.xml') -Encoding UTF8
        '<Task></Task>' | Out-File (Join-Path $taskXmlDir 'wpd.xml') -Encoding UTF8
        '<Task></Task>' | Out-File (Join-Path $taskXmlDir 'microsoft.xml') -Encoding UTF8
        '<Task></Task>' | Out-File (Join-Path $taskXmlDir 'azcmagent.xml') -Encoding UTF8
        Write-TestManifest $taskFolder
    }

    $fsrmFolder = Join-Path $runtimeFull 'PRODTEST_Baseline_FsrmFix'
    [PSCustomObject]@{Name='PRODTEST_GROUP';IncludePattern='*.tmp; *.bak';ExcludePattern='keep.tmp'} | Export-Csv (Join-Path $fsrmFolder 'fsrm_filegroups.csv') -NoTypeInformation -Encoding UTF8
    [PSCustomObject]@{Name='PRODTEST_SCREEN_TEMPLATE';Description='test';Active='True';IncludeGroup='PRODTEST_GROUP'} | Export-Csv (Join-Path $fsrmFolder 'fsrm_screen_templates.csv') -NoTypeInformation -Encoding UTF8
    [PSCustomObject]@{Path=$dataRoot;Active='True';Template='PRODTEST_SCREEN_TEMPLATE';IncludeGroup='PRODTEST_GROUP';MatchesTemplate='True'} | Export-Csv (Join-Path $fsrmFolder 'fsrm_screens_applied.csv') -NoTypeInformation -Encoding UTF8
    [PSCustomObject]@{Name='PRODTEST_QUOTA_TEMPLATE';Description='test';Size='1048576';SoftLimit='True';Threshold='85%; 100%'} | Export-Csv (Join-Path $fsrmFolder 'fsrm_quota_templates.csv') -NoTypeInformation -Encoding UTF8
    [PSCustomObject]@{Path=$dataRoot;Size='1048576';SoftLimit='True';Template='PRODTEST_QUOTA_TEMPLATE';Usage='0';MatchesTemplate='True'} | Export-Csv (Join-Path $fsrmFolder 'fsrm_quotas_applied.csv') -NoTypeInformation -Encoding UTF8
    Write-TestManifest $fsrmFolder

    $fsrmVerifyFolder = Join-Path $runtimeFull 'PRODTEST_Baseline_FsrmVerifyFail'
    foreach ($fsrmCsvName in @('fsrm_filegroups.csv','fsrm_screen_templates.csv','fsrm_screens_applied.csv',
            'fsrm_quota_templates.csv','fsrm_quotas_applied.csv')) {
        Copy-Item -LiteralPath (Join-Path $fsrmFolder $fsrmCsvName) -Destination $fsrmVerifyFolder -Force
    }
    Write-TestManifest $fsrmVerifyFolder

    $fsrmLocalizedFolder = Join-Path $runtimeFull 'PRODTEST_Baseline_FsrmLocalized'
    $frenchAudioVideoName = 'Fichiers audio et vid' + [char]0x00E9 + 'o'
    $frenchBlockAudioVideoName = 'Bloquer les fichiers audio et vid' + [char]0x00E9 + 'o'
    $frenchReportsQuotaName = 'Limite de 200 Mo pour les rapports d' + [char]0x00B4 + 'utilisateurs'
    @(
        [PSCustomObject]@{Name=$frenchAudioVideoName;IncludePattern='*.wav; *.mp3';ExcludePattern=''},
        [PSCustomObject]@{Name='Fichiers de sauvegarde';IncludePattern='*.bak';ExcludePattern=''},
        [PSCustomObject]@{Name='Fichiers compresses';IncludePattern='*.zip';ExcludePattern=''},
        [PSCustomObject]@{Name='Fichiers de courrier electronique';IncludePattern='*.msg';ExcludePattern=''},
        [PSCustomObject]@{Name='Fichiers executables';IncludePattern='*.exe';ExcludePattern=''},
        [PSCustomObject]@{Name='Fichiers image';IncludePattern='*.png';ExcludePattern=''},
        [PSCustomObject]@{Name='Fichiers Office';IncludePattern='*.docx';ExcludePattern=''},
        [PSCustomObject]@{Name='Fichier systeme';IncludePattern='*.sys';ExcludePattern=''},
        [PSCustomObject]@{Name='Fichiers temporaires';IncludePattern='*.tmp';ExcludePattern=''},
        [PSCustomObject]@{Name='Fichiers texte';IncludePattern='*.txt';ExcludePattern=''},
        [PSCustomObject]@{Name='Fichiers de pages Web';IncludePattern='*.html';ExcludePattern=''}
    ) | Export-Csv (Join-Path $fsrmLocalizedFolder 'fsrm_filegroups.csv') -NoTypeInformation -Encoding UTF8
    @(
        [PSCustomObject]@{Name=$frenchBlockAudioVideoName;Description='Francais';Active='True';IncludeGroup=$frenchAudioVideoName},
        [PSCustomObject]@{Name='Bloquer les fichiers de courrier electronique';Description='Francais';Active='True';IncludeGroup='Fichiers de courrier electronique'},
        [PSCustomObject]@{Name='Bloquer les fichiers executables';Description='Francais';Active='True';IncludeGroup='Fichiers executables'},
        [PSCustomObject]@{Name='Bloquer les fichiers image';Description='Francais';Active='True';IncludeGroup='Fichiers image'},
        [PSCustomObject]@{Name='Analyser les fichiers executables et systeme';Description='Francais';Active='False';IncludeGroup='Fichiers executables; Fichier systeme'}
    ) | Export-Csv (Join-Path $fsrmLocalizedFolder 'fsrm_screen_templates.csv') -NoTypeInformation -Encoding UTF8
    [PSCustomObject]@{Path=$dataRoot;Active='True';Template=$frenchBlockAudioVideoName;IncludeGroup=$frenchAudioVideoName;MatchesTemplate='True'} | Export-Csv (Join-Path $fsrmLocalizedFolder 'fsrm_screens_applied.csv') -NoTypeInformation -Encoding UTF8
    @(
        [PSCustomObject]@{Name='Limite de 100 Mo';Description='Francais';Size='104857600';SoftLimit='False';Threshold='100%; 85%'},
        [PSCustomObject]@{Name=$frenchReportsQuotaName;Description='Francais A';Size='209715200';SoftLimit='False';Threshold='100%; 85%'},
        [PSCustomObject]@{Name='Limite de 200 Mo avec extension de 50 Mo';Description='Francais B';Size='209715200';SoftLimit='False';Threshold='100%; 85%'}
    ) | Export-Csv (Join-Path $fsrmLocalizedFolder 'fsrm_quota_templates.csv') -NoTypeInformation -Encoding UTF8
    [PSCustomObject]@{Path=$dataRoot;Size='104857600';SoftLimit='False';Template='Limite de 100 Mo';Usage='0';MatchesTemplate='True'} | Export-Csv (Join-Path $fsrmLocalizedFolder 'fsrm_quotas_applied.csv') -NoTypeInformation -Encoding UTF8
    Write-TestManifest $fsrmLocalizedFolder

    $fsrmNativeFolder = Join-Path $runtimeFull 'PRODTEST_Baseline_FsrmNativeFix'
    Copy-Item -LiteralPath (Join-Path $fsrmFolder 'fsrm_filegroups.csv') -Destination $fsrmNativeFolder -Force
    Copy-Item -LiteralPath (Join-Path $fsrmFolder 'fsrm_screen_templates.csv') -Destination $fsrmNativeFolder -Force
    Copy-Item -LiteralPath (Join-Path $fsrmFolder 'fsrm_screens_applied.csv') -Destination $fsrmNativeFolder -Force
    Copy-Item -LiteralPath (Join-Path $fsrmFolder 'fsrm_quota_templates.csv') -Destination $fsrmNativeFolder -Force
    Copy-Item -LiteralPath (Join-Path $fsrmFolder 'fsrm_quotas_applied.csv') -Destination $fsrmNativeFolder -Force
    foreach ($nativeName in @('fsrm_filegroups.xml','fsrm_screen_templates.xml','fsrm_quota_templates.xml')) {
        '<FsrmExport />' | Out-File (Join-Path $fsrmNativeFolder $nativeName) -Encoding UTF8
    }
    [PSCustomObject]@{SchemaVersion='2.4';SelectedSteps='FSRM';FsrmNativeExport='Complete'} |
        Export-Csv (Join-Path $fsrmNativeFolder 'export_metadata.csv') -NoTypeInformation -Encoding UTF8
    Write-TestManifest $fsrmNativeFolder

    $adminFolder = Join-Path $runtimeFull 'PRODTEST_Baseline_AdminDescription'
    $adminShare = Import-Csv (Join-Path $adminFolder 'shares.csv') | Select-Object -First 1
    $adminShare.Name = 'E$'
    $adminShare.Description = 'Description automatique francaise'
    $adminShare | Export-Csv (Join-Path $adminFolder 'shares.csv') -NoTypeInformation -Encoding UTF8
    $adminPerm = Import-Csv (Join-Path $adminFolder 'shares_permissions.csv') | Select-Object -First 1
    $adminPerm.ShareName = 'E$'
    $adminPerm | Export-Csv (Join-Path $adminFolder 'shares_permissions.csv') -NoTypeInformation -Encoding UTF8
    $adminRootRows = @(Import-Csv (Join-Path $adminFolder 'acls_roots.csv'))
    foreach ($adminRootRow in $adminRootRows) { $adminRootRow.ShareName = 'E$' }
    $adminRootRows | Export-Csv (Join-Path $adminFolder 'acls_roots.csv') -NoTypeInformation -Encoding UTF8
    Write-TestManifest $adminFolder

    $systemFolder = Join-Path $runtimeFull 'PRODTEST_Baseline_SystemAclSkip'
    $systemPath = Join-Path $dataRoot '$RECYCLE.BIN\S-1-5-21-PRODTEST'
    $systemFolderRows = @(Import-Csv (Join-Path $systemFolder 'acls_folders_PRODTEST_SHARE.csv'))
    $systemFolderRows += [PSCustomObject]@{ShareName='PRODTEST_SHARE';ShareRoot=$dataRoot;Path=$systemPath;Owner='';Sddl='D:(A;;FA;;;S-1-1-0)';Protected='False';ExplicitACEs='1'}
    $systemFolderRows | Export-Csv (Join-Path $systemFolder 'acls_folders_PRODTEST_SHARE.csv') -NoTypeInformation -Encoding UTF8
    $systemInheritance = @(Import-Csv (Join-Path $systemFolder 'inheritance_map.csv'))
    $systemInheritance += [PSCustomObject]@{ShareRoot=$dataRoot;Path=$systemPath;Depth='2';InheritanceEnabled='True';BrokenInheritance='False';ExplicitACECount='99';InheritedACECount='99';Owner='';DaclSha256=('0'*64)}
    $systemInheritance | Export-Csv (Join-Path $systemFolder 'inheritance_map.csv') -NoTypeInformation -Encoding UTF8
    Write-TestManifest $systemFolder
    $driftCsv = Join-Path $runtimeFull 'PRODTEST_Baseline_DaclDrift\inheritance_map.csv'
    $driftRows = @(Import-Csv $driftCsv)
    $driftRows[1].DaclSha256 = ('0' * 64)
    $driftRows | Export-Csv $driftCsv -NoTypeInformation -Encoding UTF8
    Write-TestManifest (Split-Path $driftCsv -Parent)

    $missingCsv = Join-Path $runtimeFull 'PRODTEST_Baseline_MissingBaseline\shares_permissions.csv'
    Remove-Item -LiteralPath $missingCsv -Force
    Write-TestManifest (Split-Path $missingCsv -Parent)

    Add-Content -LiteralPath (Join-Path $runtimeFull 'PRODTEST_Baseline_CorruptFix\shares.csv') -Value 'CORRUPTED'

    $rootAceCsv = Join-Path $runtimeFull 'PRODTEST_Baseline_RootAceExtra\acls_roots.csv'
    $rootAceRows = @(Import-Csv $rootAceCsv)
    $rootAceRows = @($rootAceRows | Select-Object -Skip 1)
    $rootAceRows | Export-Csv $rootAceCsv -NoTypeInformation -Encoding UTF8
    Write-TestManifest (Split-Path $rootAceCsv -Parent)

    $crossFolder = Join-Path $runtimeFull 'PRODTEST_Baseline_CrossLocale'
    $crossPermCsv = Join-Path $crossFolder 'shares_permissions.csv'
    $crossPerm = Import-Csv $crossPermCsv | Select-Object -First 1
    $crossPerm.AccountName = 'Tout le monde'
    $crossPerm | Export-Csv $crossPermCsv -NoTypeInformation -Encoding UTF8
    $crossAclCsv = Join-Path $crossFolder 'acls_roots.csv'
    $crossAcls = @(Import-Csv $crossAclCsv)
    $frenchSystem = 'AUTORITE NT\Syst' + [char]0x00E8 + 'me'
    foreach ($row in $crossAcls) {
        $identityKey = [string]$row.IdentityReference
        switch ($identityKey.ToUpperInvariant()) {
            'BUILTIN\ADMINISTRATORS' { $row.IdentityReference = 'BUILTIN\Administrateurs' }
            'BUILTIN\USERS'          { $row.IdentityReference = 'BUILTIN\Utilisateurs' }
            'NT AUTHORITY\SYSTEM'     { $row.IdentityReference = $frenchSystem }
            'CREATOR OWNER'           { $row.IdentityReference = 'CREATEUR PROPRIETAIRE' }
            'EVERYONE'                { $row.IdentityReference = 'Tout le monde' }
        }
        if ([string]$row.Owner -ieq 'BUILTIN\Administrators') { $row.Owner = 'BUILTIN\Administrateurs' }
        if ([string]$row.Group -ieq 'NT AUTHORITY\SYSTEM')    { $row.Group = $frenchSystem }
    }
    $crossAcls | Export-Csv $crossAclCsv -NoTypeInformation -Encoding UTF8
    Write-TestManifest $crossFolder

    $savedErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $cases = @(
        @{Name='Clean'; Expected=0; Pattern='partial validation only, migration sign-off not authorized'},
        @{Name='ExtraPerm'; Expected=1; Pattern='Unexpected permission present'},
        @{Name='DaclDrift'; Expected=1; Pattern='DACL fingerprint differs'},
        @{Name='ShareDrift'; Expected=1; Pattern='EncryptData before'},
        @{Name='RootAceExtra'; Expected=1; Pattern='ACE set differs'},
        @{Name='CrossLocale'; Expected=0; Pattern='partial validation only, migration sign-off not authorized'},
        @{Name='ProviderPath'; Expected=0; Pattern='partial validation only, migration sign-off not authorized'},
        @{Name='ManifestOnly'; Expected=0; Pattern='partial validation only, migration sign-off not authorized'},
        @{Name='TaskFixBlocked'; Expected=1; Pattern='Task fix blocked'},
        @{Name='TaskFilteredFix'; Expected=0; Pattern='Task imported from'},
        @{Name='TaskAllEligible'; Expected=0; Pattern='Microsoft/Windows OS task: not imported'},
        @{Name='TaskBadPattern'; Expected=1; Pattern='nothing was imported for this pattern'},
        @{Name='FsrmFix'; Expected=0; Pattern='Quota template PRODTEST_QUOTA_TEMPLATE : Created from baseline'},
        @{Name='FsrmLocalized'; Expected=0; Pattern="Equivalent localized object found as '200 MB Limit Reports to User'"},
        @{Name='FsrmNativeFix'; Expected=0; Pattern='Restored from native XML; threshold actions preserved'},
        @{Name='FsrmVerifyFail'; Expected=1; Pattern='post-fix verification failed'},
        @{Name='AdminDescription'; Expected=0; Pattern='partial validation only, migration sign-off not authorized'},
        @{Name='SystemAclSkip'; Expected=0; Pattern='system-managed row(s) skipped'},
        @{Name='VolumeStable'; Expected=0; Pattern='Stable mapping verified by VolumeUniqueId'},
        @{Name='VolumeLetterDrift'; Expected=1; Pattern='drive letter is F:'},
        @{Name='LocalAccountsClean'; Expected=0; Pattern='Administrators membership present'},
        @{Name='LocalAdminExtra'; Expected=1; Pattern='Unexpected destination member has local Administrators rights'},
        @{Name='MissingBaseline'; Expected=1; Pattern='Required by selected check'},
        @{Name='CorruptFix'; Expected=1; Pattern='All fixes disabled'}
    )
    foreach ($case in $cases) {
        $output = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath `
            -ChildScenario $case.Name -TestRoot $runtimeFull *>&1
        $code = $LASTEXITCODE
        $text = $output -join "`n"
        if ($code -ne $case.Expected -or $text -notmatch [regex]::Escape($case.Pattern)) {
            $failures.Add("$($case.Name) expected exit $($case.Expected) and '$($case.Pattern)', got exit $code")
            Write-Host ("OUTPUT {0} :`n{1}" -f $case.Name, $text) -ForegroundColor DarkYellow
        } else {
            Write-Host "PASS : $($case.Name)"
        }
    }
    if (Test-Path -LiteralPath (Join-Path $runtimeFull 'PRODTEST_NewShareCalled.txt')) {
        $failures.Add('CorruptFix called New-SmbShare despite failed manifest verification')
    }
    $registeredTaskMarker = Join-Path $runtimeFull 'PRODTEST_TasksRegistered_TaskFilteredFix.txt'
    if (-not (Test-Path -LiteralPath $registeredTaskMarker) -or
        @((Get-Content -LiteralPath $registeredTaskMarker) | Where-Object { $_ -eq '\CUSTOM\PRODTEST_CUSTOM' }).Count -ne 1) {
        $failures.Add('TaskFilteredFix did not import exactly the selected CUSTOM task')
    }
    if (-not (Test-Path -LiteralPath $registeredTaskMarker) -or
        @((Get-Content -LiteralPath $registeredTaskMarker) | Where-Object { $_ -eq '\Start_Windows_Update' }).Count -ne 1) {
        $failures.Add('TaskFilteredFix did not import the selected root task without a leading slash in TaskInclude')
    }
    if ((Test-Path -LiteralPath $registeredTaskMarker) -and
        @((Get-Content -LiteralPath $registeredTaskMarker) | Where-Object { $_ -like '\WPD\*' }).Count -gt 0) {
        $failures.Add('TaskFilteredFix imported a generated WPD task')
    }
    $allTaskMarker = Join-Path $runtimeFull 'PRODTEST_TasksRegistered_TaskAllEligible.txt'
    if (-not (Test-Path -LiteralPath $allTaskMarker) -or
        @((Get-Content -LiteralPath $allTaskMarker) | Where-Object {
            $_ -eq '\CUSTOM\PRODTEST_CUSTOM' -or $_ -eq '\Start_Windows_Update'
        }).Count -ne 2) {
        $failures.Add('TaskAllEligible did not import exactly the two eligible tasks')
    }
    if ((Test-Path -LiteralPath $allTaskMarker) -and
        @((Get-Content -LiteralPath $allTaskMarker) | Where-Object {
            $_ -like '\WPD\*' -or $_ -like '\Microsoft\*' -or $_ -eq '\azcmagent'
        }).Count -gt 0) {
        $failures.Add('TaskAllEligible imported an OS-specific, agent-managed or per-user SID task')
    }
    $fsrmMarker = Join-Path $runtimeFull 'PRODTEST_FsrmCreated_FsrmFix.txt'
    if (-not (Test-Path -LiteralPath $fsrmMarker) -or @(Get-Content -LiteralPath $fsrmMarker).Count -ne 2) {
        $failures.Add('FSRM fix scenarios did not create the expected screens and quotas')
    }
    $nativeImportMarker = Join-Path $runtimeFull 'PRODTEST_FsrmNativeImports.txt'
    if (-not (Test-Path -LiteralPath $nativeImportMarker) -or @(Get-Content -LiteralPath $nativeImportMarker).Count -ne 3) {
        $failures.Add('FsrmNativeFix did not import exactly three native FSRM objects')
    }
    $nativeResetMarker = Join-Path $runtimeFull 'PRODTEST_FsrmNativeResets.txt'
    if (-not (Test-Path -LiteralPath $nativeResetMarker) -or @(Get-Content -LiteralPath $nativeResetMarker).Count -ne 2) {
        $failures.Add('FsrmNativeFix did not reset the existing screen and quota from their templates')
    }

    $depthOutput = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath `
        -ChildScenario ExportDepth -TestRoot $runtimeFull *>&1
    $depthCode = $LASTEXITCODE
    $depthCsv = Join-Path $runtimeFull 'PRODTEST_ExportDepth\inheritance_map.csv'
    $depthRows = if (Test-Path $depthCsv) { @(Import-Csv $depthCsv) } else { @() }
    if ($depthCode -ne 0 -or $depthRows.Count -ne $allDirs.Count -or [int]$depthRows[-1].Depth -ne 7) {
        $failures.Add("ExportDepth expected $($allDirs.Count) rows through depth 7, got $($depthRows.Count), exit $depthCode")
    } else {
        Write-Host 'PASS : ExportDepth'
    }

    $existingRoot = Join-Path $runtimeFull 'PRODTEST_ExistingRoot'
    New-Item -ItemType Directory -Path $existingRoot | Out-Null
    Set-Content -LiteralPath (Join-Path $existingRoot 'PRODTEST_stale.txt') -Value 'stale'
    $existingOutput = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath `
        -ChildScenario ExistingRoot -TestRoot $runtimeFull *>&1
    if ($LASTEXITCODE -eq 0 -or (($existingOutput -join "`n") -notmatch 'ExportRoot is not empty')) {
        $failures.Add('ExistingRoot should refuse a non-empty export directory')
    } else {
        Write-Host 'PASS : ExistingRoot'
    }

    $taskOutput = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath `
        -ChildScenario TaskCollision -TestRoot $runtimeFull *>&1
    $taskCode = $LASTEXITCODE
    $taskCsv = Join-Path $runtimeFull 'PRODTEST_TaskCollision\scheduled_tasks.csv'
    $taskRows = if (Test-Path $taskCsv) { @(Import-Csv $taskCsv) } else { @() }
    $uniqueXml = @($taskRows | Select-Object -ExpandProperty TaskXmlFile -Unique)
    $xmlCount = @(Get-ChildItem (Join-Path $runtimeFull 'PRODTEST_TaskCollision\scheduled_tasks\*.xml') -ErrorAction SilentlyContinue).Count
    if ($taskCode -ne 0 -or $taskRows.Count -ne 2 -or $uniqueXml.Count -ne 2 -or $xmlCount -ne 2) {
        $failures.Add("TaskCollision expected two unique XML files, got rows=$($taskRows.Count), unique=$($uniqueXml.Count), files=$xmlCount, exit=$taskCode")
    } else {
        Write-Host 'PASS : TaskCollision'
    }

    $fsrmExportOutput = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath `
        -ChildScenario FsrmExport -TestRoot $runtimeFull *>&1
    $fsrmExportCode = $LASTEXITCODE
    $fsrmExportFolder = Join-Path $runtimeFull 'PRODTEST_FsrmExport'
    $fsrmExportMetadata = if (Test-Path (Join-Path $fsrmExportFolder 'export_metadata.csv')) {
        Import-Csv (Join-Path $fsrmExportFolder 'export_metadata.csv') | Select-Object -First 1
    } else { $null }
    $nativeExportCount = @(Get-ChildItem (Join-Path $fsrmExportFolder 'fsrm_*.xml') -ErrorAction SilentlyContinue).Count
    $emptyQuotaRows = if (Test-Path (Join-Path $fsrmExportFolder 'fsrm_quotas_applied.csv')) {
        @(Import-Csv (Join-Path $fsrmExportFolder 'fsrm_quotas_applied.csv')).Count
    } else { -1 }
    if ($fsrmExportCode -ne 0 -or $null -eq $fsrmExportMetadata -or
        $fsrmExportMetadata.SchemaVersion -ne '2.5' -or $fsrmExportMetadata.FsrmNativeExport -ne 'Complete' -or
        $nativeExportCount -ne 3 -or $emptyQuotaRows -ne 0) {
        $failures.Add("FsrmExport expected schema 2.5, three native XML files and an empty quota CSV, exit=$fsrmExportCode")
        Write-Host ("OUTPUT FsrmExport :`n{0}" -f ($fsrmExportOutput -join "`n")) -ForegroundColor DarkYellow
    } else {
        Write-Host 'PASS : FsrmExport'
    }

    $localExportOutput = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath `
        -ChildScenario LocalAccountsExport -TestRoot $runtimeFull *>&1
    $localExportCode = $LASTEXITCODE
    $localExportFolder = Join-Path $runtimeFull 'PRODTEST_LocalAccountsExport'
    $localExportMetadata = if (Test-Path (Join-Path $localExportFolder 'export_metadata.csv')) {
        Import-Csv (Join-Path $localExportFolder 'export_metadata.csv') | Select-Object -First 1
    } else { $null }
    $localUsersCount = if (Test-Path (Join-Path $localExportFolder 'local_users.csv')) {
        @(Import-Csv (Join-Path $localExportFolder 'local_users.csv')).Count
    } else { -1 }
    $localMembersCount = if (Test-Path (Join-Path $localExportFolder 'local_administrators_members.csv')) {
        @(Import-Csv (Join-Path $localExportFolder 'local_administrators_members.csv')).Count
    } else { -1 }
    if ($localExportCode -ne 0 -or $null -eq $localExportMetadata -or
        $localExportMetadata.SchemaVersion -ne '2.5' -or $localUsersCount -ne 2 -or $localMembersCount -ne 2) {
        $failures.Add("LocalAccountsExport expected schema 2.5, two users and two Administrators members, exit=$localExportCode")
        Write-Host ("OUTPUT LocalAccountsExport :`n{0}" -f ($localExportOutput -join "`n")) -ForegroundColor DarkYellow
    } else {
        Write-Host 'PASS : LocalAccountsExport'
    }

    $fixDi = New-Object System.IO.DirectoryInfo($dataRoot)
    $beforeFix = $fixDi.GetAccessControl('Access')
    $expectedFixSddl = $beforeFix.GetSecurityDescriptorSddlForm('Access')
    $changedFix = $fixDi.GetAccessControl('Access')
    $changedFix.SetAccessRuleProtection((-not $changedFix.AreAccessRulesProtected), $true)
    $fixDi.SetAccessControl($changedFix)
    $folderFixOutput = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath `
        -ChildScenario FolderFix -TestRoot $runtimeFull *>&1
    $folderFixCode = $LASTEXITCODE
    $afterFixSddl = $fixDi.GetAccessControl('Access').GetSecurityDescriptorSddlForm('Access')
    if ($folderFixCode -ne 0 -or ($folderFixOutput -join "`n") -notmatch 're-applied and verified' -or
        (Get-NormalizedTestDacl $afterFixSddl) -ne (Get-NormalizedTestDacl $expectedFixSddl)) {
        $failures.Add("FolderFix did not restore and verify the PRODTEST DACL, exit=$folderFixCode")
        Write-Host ("OUTPUT FolderFix :`n{0}" -f ($folderFixOutput -join "`n")) -ForegroundColor DarkYellow
        Write-Host "EXPECTED DACL: $expectedFixSddl" -ForegroundColor DarkYellow
        Write-Host "ACTUAL DACL  : $afterFixSddl" -ForegroundColor DarkYellow
    } else {
        Write-Host 'PASS : FolderFix'
    }
    $ErrorActionPreference = $savedErrorActionPreference
} finally {
    if (Test-Path -LiteralPath $runtimeFull) { Remove-Item -LiteralPath $runtimeFull -Recurse -Force }
}

if ($failures.Count -gt 0) {
    foreach ($failure in $failures) { Write-Host "FAIL : $failure" -ForegroundColor Red }
    exit 1
}
Write-Host 'ALL PRODTEST PROD SAFETY TESTS PASSED' -ForegroundColor Green
exit 0
