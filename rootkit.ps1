[CmdletBinding()]
param( 
    $msg = "Hello World"
)

Function Encode {
    param( 
        [Parameter(Mandatory=$true)][String]$msg    # string to be encoded - REQUIRED
    )
    $chararray = [System.Text.Encoding]::Unicode.GetBytes($msg)
    $b64 = [System.Convert]::ToBase64String($chararray)
    Write-Verbose "Encoded `"$msg`" to `"$b64`""
    return $b64
}
Function Decode {
    param( 
        [Parameter(Mandatory=$true)][String]$encoded # string to be decoded - REQUIRED
    )
    $charstring = [System.Convert]::FromBase64String($encoded)
    $decoded = [System.Text.Encoding]::Unicode.GetString($charstring)
    Write-Verbose "Decoded `"$encoded`" to `"$decoded`""
    return $decoded

}
Function Query-Hardware {
    # query various virtual hardware entries with WMI
    $model = (Get-WmiObject -class Win32_ComputerSystem).Model
    $disk = (Get-WmiObject -Class Win32_DiskDrive).Model

    # VirtualBox block
    if (($model -like "*virtualbox*") -or ($disk -like "*vbox*")) {
        $bios = (Get-WmiObject -class Win32_BIOS).SMBIOSBIOSVersion
        Write-Verbose "     VirtualBox     "
    }
    # VMWare block
    elseif (($model -like "*vmware*") -or ($disk -like "*vmware*")) {
        # NOTE: Different property than VirtualBox
        $bios = (Get-WmiObject -class Win32_BIOS).SerialNumber
        Write-Verbose "     VMWare     "
    }
    else {
        Write-Verbose "Found no signs of being inside a VM"
        return $false    # No signs of VMWare or VirtualBox use
    }
    # output the rest of the VM information to the VERBOSE stream
    Write-Verbose "--------------------"
    Write-Verbose "System Model: $model"
    Write-Verbose "BIOS Serial Number: $bios"
    Write-Verbose "Harddisk: $disk"
    return $true    # we ARE in a VM
}
<#
    Source: https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/
    Must be run from an interface before a script is run
#>
Function Disable-ExecutionPolicy {
    $mgr = New-Object System.Management.Automation.AuthorizationManager "Microsoft.PowerShell"
    $exec = ($ctx = $executioncontext.gettype().getfield("_context","nonpublic,instance").getvalue( $executioncontext)).gettype()
    $exec.getfield("_authorizationManager","nonpublic,instance").setvalue($ctx, $mgr)
}

Query-Hardware
Decode $(Encode $msg)