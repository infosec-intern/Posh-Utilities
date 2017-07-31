# Posh-Utilities
A series of commonly-used Cmdlets that I can't find in standard PowerShell

## Get-ScriptBlock
Extract scriptblocks held in the PowerShell Applications and Services event log

## Get-BITSHistory
Analyze event logs for information about previous Background Intelligent Transfer sessions (also known as BITS)

## Get-WSManCommands
Analyze event logs for information about any PSSession remote management sessions (also known as WSMan)

## Posh-Zip
A couple zip/unzip functions: Invoke-Zip and Invoke-Unzip
* Invoke-Zip: Compress a folder or collection of files into an archive
* Invoke-Unzip: Extract an archive to a specific folder

## Disable-WinRM
A quick script to undo the various settings enabled by `winrm quickconfig`

Quickconfig output shows:
```
WinRM service type changed to delayed auto start.
WinRM service started.
Created a WinRM listener on HTTP://* to accept WS-Man requests to any IP on this machine.
```
More info about enabling WinRM can be found at [MSDN](!https://msdn.microsoft.com/en-us/library/aa384372(v=vs.85).aspx)

## Encoder
Base64 encoder and simple XOR encryptor. As far as the base64 encoder goes, the `rootkit.ps1` file has an easier-to-use encode/decode function imo

## Query-VM
Super quick test of using WMI to identify default VirtualBox and VMWare keys.

Should be expanded upon later when I can do some more research on registry and hardware keys
