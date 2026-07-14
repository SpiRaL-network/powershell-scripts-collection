# PowerShell Scripts Collection

A personal collection of PowerShell scripts I use to automate Windows tasks.
Each script lives in its own folder with a dedicated README explaining what it
does and how to use it.

## Scripts

| Script | Description | Link |
|--------|-------------|------|
| **Set-VM-Start-Shutdown** | Auto-start a VMware Workstation VM at logon and cleanly shut it down when the host powers off. Generic (any VM), with a file-picker and self-elevation. | [📂 folder](./Set-VM-Start-Shutdown) |

## Usage

Clone the repo and run any script from its folder:

```powershell
git clone https://github.com/<your-user>/powershell-scripts-collection.git
cd powershell-scripts-collection
```

Most scripts require an elevated (Administrator) PowerShell session; the ones
that do will self-elevate via UAC when needed.

## Requirements

- Windows 10 / 11
- Windows PowerShell 5.1 or PowerShell 7+
- Per-script requirements are listed in each script's own README.

## License

MIT — see [LICENSE](./LICENSE).
