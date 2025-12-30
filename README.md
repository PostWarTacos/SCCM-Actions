# SCCM Actions

A collection of PowerShell scripts for managing and troubleshooting Microsoft System Center Configuration Manager (SCCM) client operations.

## Scripts

### Main Scripts
- **Check-InstallLogs.ps1** - Check SCCM installation logs
- **Get-SCCMRunningActions.ps1** - Display currently running SCCM actions
- **Get-SCCMScheduled.ps1** - View scheduled SCCM tasks
- **Get-SMSCode.ps1** - Retrieve SMS codes

### Repair-SCCM
Scripts for repairing SCCM client installations:
- **Invoke-SCCMRepair.ps1** - Main repair script
- **Resources/Check-SCCMHealth.ps1** - Verify SCCM client health
- **Resources/Reinstall-SCCM.ps1** - Reinstall SCCM client
- **Resources/Remove-SCCM.ps1** - Remove SCCM client

### Repair-WIP
Work-in-progress repair utilities:
- **Create-SCCMScheduledTasks.ps1** - Create scheduled tasks for SCCM maintenance

## Usage

Run scripts with appropriate PowerShell permissions. Most scripts require administrative privileges.

```powershell
# Example: Check running SCCM actions
.\Get-SCCMRunningActions.ps1

# Example: Invoke SCCM repair
.\Repair-SCCM\Invoke-SCCMRepair.ps1
```

## Requirements

- Windows PowerShell 5.1 or later
- SCCM Client installed
- Administrative privileges

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

Copyright (c) 2025 PostWarTacos
