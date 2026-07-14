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

## Disclaimer / Avertissement

> **EN** — These scripts are provided **"as is"**, without any warranty. Several
> of them modify Windows system settings (scheduled tasks, Group Policy, registry,
> services) and require Administrator rights. **Review each script and test it in
> a safe environment before running it.** You run them at your own risk; the
> author accepts **no liability** for any data loss or system damage.
>
> **FR** — Ces scripts sont fournis **« tels quels »**, sans aucune garantie.
> Plusieurs modifient des paramètres système Windows (tâches planifiées, stratégie
> de groupe, registre, services) et nécessitent les droits administrateur.
> **Relis chaque script et teste-le dans un environnement sûr avant de l'exécuter.**
> Tu les utilises à tes propres risques ; l'auteur décline **toute responsabilité**
> en cas de perte de données ou de dommage système.

## License

MIT — see [LICENSE](./LICENSE).
