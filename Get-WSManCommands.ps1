<#
.SYNOPSIS
    Analyze event logs for information about any PSSession remote management sessions (also known as WSMan)
.DESCRIPTION
    Analyze event logs for information about any PSSession remote management sessions (also known as WSMan).
    This includes when sessions are started and stopped, extracting any hex-encoded commands run during the sessions,
    and reporting any errors that occurred during the sessions
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
