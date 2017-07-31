[CmdletBinding()]
param()

Function Query-VM {
    # query various virtual hardware entries with WMI
    $model = (Get-WmiObject -class Win32_ComputerSystem).Model
    $disk = (Get-WmiObject -Class Win32_DiskDrive).Model

    # VirtualBox block
    if (($model -like "*virtualbox*") -or ($disk -like "*vbox*")) {
        $bios = (Get-WmiObject -class Win32_BIOS).SMBIOSBIOSVersion
        Write-Verbose "     VirtualBox     "
        Write-Verbose "--------------------"
        Write-Verbose "System Model: $model"
        Write-Verbose "BIOS: $bios"
        Write-Verbose "Harddisk: $disk"
        return $true    # we ARE in a VM
    }
    # VMWare block
    elseif (($model -like "*vmware*") -or ($disk -like "*vmware*")) {
        # NOTE: Different property than VirtualBox
        $bios = (Get-WmiObject -class Win32_BIOS).SerialNumber
        Write-Verbose "     VMWare     "
        Write-Verbose "--------------------"
        Write-Verbose "System Model: $model"
        Write-Verbose "BIOS Serial Number: $bios"
        Write-Verbose "Harddisk: $disk"

        return $true
    }
    return $false    # No signs of VMWare or VirtualBox use
}

$VerbosePreference = "Continue"
$vm = Query-VM

Write-Output "[*] Presence of Virtual Machine: $vm"