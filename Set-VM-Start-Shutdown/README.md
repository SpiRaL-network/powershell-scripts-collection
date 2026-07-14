# Set-VM-Start-Shutdown

Configure a **VMware Workstation** VM to:

1. **Auto-start at logon** — a shortcut in the Startup folder runs
   `vmware.exe -x <vmx>` when you log in.
2. **Shut down cleanly at host shutdown** — a Group Policy shutdown script runs
   `vmrun stop <vmx> soft` when Windows powers off. Windows *waits* for Group
   Policy shutdown scripts (unlike scheduled tasks), so the guest gets a clean
   ACPI shutdown instead of being cut off.

It is fully **generic** (works for any VM), **idempotent** (safe to re-run), and
**self-elevating** (asks for Administrator via UAC when needed).

## Why not just close VMware on shutdown?

By default, when the host shuts down, a running VM may be suspended or simply
killed by Windows after a timeout — effectively pulling the plug on the guest.
This script guarantees a graceful `soft` power-off instead.

## Usage

Right-click the script → **Run with PowerShell**, or from a terminal:

```powershell
# Deploy: opens a file-picker to choose the .vmx, then configures it
.\Set-VM-Start-Shutdown.ps1

# Remove: opens a picker, then cleans up shortcut + shutdown script for that VM
.\Set-VM-Start-Shutdown.ps1 -Remove

# Skip the picker by passing the path directly
.\Set-VM-Start-Shutdown.ps1 -VmxPath "D:\VMs\Kali\Kali.vmx"
```

You don't need to open an elevated shell yourself — run it, accept the UAC
prompt, pick the VM in the dialog, done.

## Parameters

| Parameter | Description |
|-----------|-------------|
| `-VmxPath` | Full path to the VM's `.vmx` file. If omitted, a file-picker dialog opens. |
| `-VmwareDir` | VMware Workstation install folder. Auto-detected if omitted. |
| `-Remove` | Undo everything for the selected VM (removes shortcut + shutdown script). |

The VM name is derived automatically from the `.vmx` file name, so multiple VMs
can be configured side by side.

## What it changes

| Mechanism | Location |
|-----------|----------|
| Startup shortcut | `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\Start <Name> VM.lnk` |
| Shutdown script | `C:\Windows\System32\GroupPolicy\Machine\Scripts\Shutdown\stop-<Name>-vm.bat` |
| GP registration | `scripts.ini`, `gpt.ini`, and the Group Policy `Scripts\Shutdown` registry keys |

## Requirements

- **VMware Workstation** (auto-detected from the registry or standard install paths).
- **VMware Tools** installed in the guest — required for the `soft` (graceful)
  shutdown to work. The script reports the Tools state at the end; it must read
  `running`.
- **Administrator rights** — the script self-elevates.

## Notes

- The shutdown mechanism uses a **Local Group Policy** shutdown script. If you
  ever want to inspect or remove it manually, see
  `gpedit.msc` → *Computer Configuration → Windows Settings → Scripts
  (Startup/Shutdown) → Shutdown*.
- After a Windows reinstall, just re-run the script to redeploy everything.
