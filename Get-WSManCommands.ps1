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
[CmdletBinding()]

Param(
    [Parameter(ParameterSetName="List")]
    [switch]$List,
    [Parameter(ParameterSetName="Computer")]
    [string]$ComputerName,
    [Parameter(ParameterSetName="Computer")]
    [PSCredential]$Credential
)
