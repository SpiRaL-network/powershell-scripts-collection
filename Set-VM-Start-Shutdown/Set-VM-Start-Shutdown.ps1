<#
.SYNOPSIS
    Configure a VMware Workstation VM to auto-start at login and shut down cleanly
    when the host shuts down. Re-run as-is after a Windows reinstall.

.DESCRIPTION
    Two mechanisms are deployed for the VM you pick:
      1) A shortcut in the Startup folder -> runs "vmware.exe -x <vmx>" at logon.
      2) A Group Policy shutdown script (Machine\Scripts\Shutdown) -> "vmrun stop <vmx> soft"
         when the host shuts down. Windows WAITS for GP shutdown scripts (unlike scheduled
         tasks), so the guest gets a clean ACPI shutdown (soft, via VMware Tools).

    Fully generic: works for ANY VM. If you don't pass -VmxPath, a file-picker window
    opens so you just click the .vmx target. The VM name is derived from the file name.
    The script self-elevates to Administrator and is idempotent (safe to re-run).

.PARAMETER VmxPath
    Full path to the VM's .vmx file. If omitted, a file-picker dialog opens.

.PARAMETER VmwareDir
    VMware Workstation install folder. Auto-detected if omitted.

.PARAMETER Remove
    Undo everything for the selected VM (removes shortcut + shutdown script).

.EXAMPLE
    .\Set-VM-Start-Shutdown.ps1
        Opens a picker, then deploys for the chosen VM.

.EXAMPLE
    .\Set-VM-Start-Shutdown.ps1 -Remove
        Opens a picker, then removes the config for the chosen VM.
#>

[CmdletBinding()]
param(
    [string]$VmxPath,
    [string]$VmwareDir,
    [switch]$Remove
)

$ErrorActionPreference = 'Stop'

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

# --- Self-elevate to Administrator (GP + HKLM require it) ---------------------
if (-not (Test-Admin)) {
    Write-Host "Elevating to Administrator..." -ForegroundColor Yellow
    $fwd = @("-ExecutionPolicy","Bypass","-File","`"$PSCommandPath`"")
    if ($VmxPath)   { $fwd += @("-VmxPath","`"$VmxPath`"") }
    if ($VmwareDir) { $fwd += @("-VmwareDir","`"$VmwareDir`"") }
    if ($Remove)    { $fwd += "-Remove" }
    Start-Process powershell -Verb RunAs -ArgumentList $fwd
    return
}

Add-Type -AssemblyName System.Windows.Forms

# --- Pick the .vmx via a dialog if not supplied ------------------------------
if (-not $VmxPath) {
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Title  = "Select the VM (.vmx) to configure"
    $dlg.Filter = "VMware VM (*.vmx)|*.vmx|All files (*.*)|*.*"
    $guess = "$env:USERPROFILE\Documents\Virtual Machines"
    if (Test-Path $guess) { $dlg.InitialDirectory = $guess }
    if ($dlg.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
        Write-Host "Cancelled - no VM selected." -ForegroundColor Yellow
        return
    }
    $VmxPath = $dlg.FileName
}

if (-not (Test-Path $VmxPath)) { throw ".vmx not found: $VmxPath" }
$VmxPath = (Resolve-Path $VmxPath).Path
$Name    = [System.IO.Path]::GetFileNameWithoutExtension($VmxPath)

# --- Auto-detect VMware install folder ---------------------------------------
if (-not $VmwareDir) {
    $cand = @(
        (Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\VMware, Inc.\VMware Workstation" -ErrorAction SilentlyContinue).InstallPath,
        (Get-ItemProperty "HKLM:\SOFTWARE\VMware, Inc.\VMware Workstation" -ErrorAction SilentlyContinue).InstallPath,
        "C:\Program Files (x86)\VMware\VMware Workstation",
        "C:\Program Files\VMware\VMware Workstation"
    ) | Where-Object { $_ -and (Test-Path (Join-Path $_ "vmrun.exe")) }
    if (-not $cand) { throw "VMware Workstation not found. Pass -VmwareDir explicitly." }
    $VmwareDir = $cand[0].TrimEnd('\')
}
$vmwareExe = Join-Path $VmwareDir "vmware.exe"
$vmrunExe  = Join-Path $VmwareDir "vmrun.exe"

# --- Common paths ------------------------------------------------------------
$startup = [Environment]::GetFolderPath('Startup')
$lnkPath = Join-Path $startup "Start $Name VM.lnk"
$gp      = "C:\Windows\System32\GroupPolicy"
$shutDir = Join-Path $gp "Machine\Scripts\Shutdown"
$batName = "stop-$Name-vm.bat"
$batPath = Join-Path $shutDir $batName
$iniPath = Join-Path $gp "Machine\Scripts\scripts.ini"
$scriptsCse = "[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}]"
$regBases = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Shutdown",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Shutdown")

Write-Host "=== Set-VM-Start-Shutdown : $Name ===" -ForegroundColor Cyan
Write-Host "  VMX    : $VmxPath"
Write-Host "  VMware : $VmwareDir"

# =============================================================================
# REMOVE mode
# =============================================================================
if ($Remove) {
    if (Test-Path $lnkPath) { Remove-Item $lnkPath -Force; Write-Host "[-] Startup shortcut removed." -ForegroundColor Green }
    if (Test-Path $batPath) { Remove-Item $batPath -Force; Write-Host "[-] Shutdown script removed." -ForegroundColor Green }
    # Only clear the GP registration if no other shutdown .bat remains
    $remaining = @(Get-ChildItem $shutDir -Filter *.bat -ErrorAction SilentlyContinue)
    if ($remaining.Count -eq 0) {
        foreach ($base in $regBases) { if (Test-Path "$base\0") { Remove-Item "$base\0" -Recurse -Force } }
        if (Test-Path $iniPath) { Remove-Item $iniPath -Force }
        Write-Host "[-] GP shutdown-script registration cleared (no scripts left)." -ForegroundColor Green
    } else {
        Write-Host "[i] Other shutdown scripts remain; GP registration kept." -ForegroundColor Yellow
    }
    & gpupdate /force | Out-Null
    Write-Host "=== Removed for '$Name'. ===" -ForegroundColor Cyan
    Read-Host "Press Enter to close"
    return
}

# =============================================================================
# DEPLOY mode
# =============================================================================
if (-not (Test-Path $vmwareExe)) { throw "vmware.exe not found: $vmwareExe" }
if (-not (Test-Path $vmrunExe))  { throw "vmrun.exe not found: $vmrunExe" }

# --- 1) Startup shortcut (at logon) ------------------------------------------
$shell = New-Object -ComObject WScript.Shell
$sc    = $shell.CreateShortcut($lnkPath)
$sc.TargetPath       = $vmwareExe
$sc.Arguments        = "-x `"$VmxPath`""       # -x = auto power on
$sc.WorkingDirectory = $VmwareDir
$sc.Description       = "Auto-start VM $Name at logon"
$sc.Save()
Write-Host "[OK] Startup shortcut : $lnkPath" -ForegroundColor Green

# --- 2) Group Policy shutdown script (at host shutdown) ----------------------
New-Item -ItemType Directory -Force -Path $shutDir | Out-Null

@"
@echo off
"$vmrunExe" stop "$VmxPath" soft
"@ | Set-Content -Path $batPath -Encoding Ascii
Write-Host "[OK] Shutdown script  : $batPath" -ForegroundColor Green

# scripts.ini: enumerate every .bat present so multiple VMs coexist
$bats = @(Get-ChildItem $shutDir -Filter *.bat | Sort-Object Name)
$lines = "[Shutdown]`r`n"
for ($i = 0; $i -lt $bats.Count; $i++) {
    $lines += "$i`CmdLine=$($bats[$i].Name)`r`n$i`Parameters=`r`n"
}
Set-Content -Path $iniPath -Value $lines -Encoding Unicode
(Get-Item $iniPath -Force).Attributes = 'Hidden,System,Archive'

# Registry: one numbered entry per .bat, in both Scripts + State branches
foreach ($base in $regBases) {
    if (Test-Path "$base\0") { Remove-Item "$base\0" -Recurse -Force }
    New-Item -Path "$base\0" -Force | Out-Null
    Set-ItemProperty "$base\0" -Name DisplayName   -Value "Local Group Policy"
    Set-ItemProperty "$base\0" -Name FileSysPath   -Value "$gp\Machine"
    Set-ItemProperty "$base\0" -Name "GPO-ID"      -Value "LocalGPO"
    Set-ItemProperty "$base\0" -Name GPOName       -Value "Local Group Policy"
    Set-ItemProperty "$base\0" -Name "SOM-ID"      -Value "Local"
    New-ItemProperty "$base\0" -Name PSScriptOrder -Value 2 -PropertyType DWord -Force | Out-Null
    for ($i = 0; $i -lt $bats.Count; $i++) {
        New-Item -Path "$base\0\$i" -Force | Out-Null
        Set-ItemProperty "$base\0\$i" -Name Script       -Value $bats[$i].Name
        Set-ItemProperty "$base\0\$i" -Name Parameters   -Value ""
        New-ItemProperty "$base\0\$i" -Name IsPowershell -Value 0 -PropertyType DWord -Force | Out-Null
        New-ItemProperty "$base\0\$i" -Name ExecTime     -Value 0 -PropertyType QWord -Force | Out-Null
    }
}
Write-Host "[OK] Group Policy registry keys written ($($bats.Count) script(s))." -ForegroundColor Green

# gpt.ini: ensure Scripts CSE registered + bump the machine version word
$gptPath = Join-Path $gp "gpt.ini"
$cseLine = ""; $version = 0
if (Test-Path $gptPath) {
    foreach ($l in Get-Content $gptPath) {
        if ($l -match '^gPCMachineExtensionNames=(.*)$') { $cseLine = $Matches[1] }
        if ($l -match '^Version=(\d+)$')                 { $version = [int]$Matches[1] }
    }
}
if ($cseLine -notmatch '42B5FAAE') { $cseLine += $scriptsCse }
$version += 0x10000
@"
[General]
gPCMachineExtensionNames=$cseLine
Version=$version
"@ | Set-Content -Path $gptPath -Encoding Ascii
Write-Host "[OK] gpt.ini updated (Version=$version)." -ForegroundColor Green

Write-Host "Applying policy (gpupdate /force)..." -ForegroundColor Cyan
& gpupdate /force | Out-Null

# --- Confirm VMware Tools (soft shutdown depends on it) -----------------------
$tools = "unknown"
try { $tools = (& $vmrunExe checkToolsState $VmxPath 2>$null | Select-Object -First 1) } catch {}

Write-Host ""
Write-Host "=== Done for '$Name' ===" -ForegroundColor Cyan
Write-Host "  Start : VM launches at logon."
Write-Host "  Stop  : VM shuts down cleanly (soft) at host shutdown."
Write-Host "  VMware Tools state: $tools  (must be 'running' for a clean soft stop)"
Write-Host "  Quick test: double-click '$lnkPath'"
Read-Host "Press Enter to close"
