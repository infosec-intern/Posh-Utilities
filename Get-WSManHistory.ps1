<#
.SYNOPSIS
    Analyze event logs for information about any PSSession remote management sessions (also known as WSMan)
.DESCRIPTION
    Analyze event logs for information about any PSSession remote management sessions (also known as WSMan).
    This includes when sessions are started and stopped, extracting any hex-encoded commands run during the sessions,
    and reporting any errors that occurred during the sessions
.PARAMETER ComputerName
    Remote computer to search event logs on. Default is the local computer
.PARAMETER Credential
    PSCredential object to authenticate to a remote computer with
.PARAMETER List
    List the WSMan sessions and their start/stop times
.EXAMPLE
    .\Get-WSManCommands.ps1
.LINK
    https://github.com/infosec-intern/Posh-Utilities/
#>
[CmdletBinding(DefaultParameterSetName="List")]

Param(
    [Parameter()]
    [string]$ComputerName = "$env:COMPUTERNAME",
    [Parameter()]
    [PSCredential]$Credential,
    [Parameter(ParameterSetName="List")]
    [switch]$List
)

$EventLogFilter = @{
    "ProviderName"="Microsoft-Windows-WinRM"
}

If ($Credential) {
    $Events = Get-WinEvent -ComputerName $ComputerName -Credential $Credential -FilterHashtable $EventLogFilter
}
Else {
    $Events = Get-WinEvent -ComputerName $ComputerName -FilterHashtable $EventLogFilter
}
