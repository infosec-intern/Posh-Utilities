<#
    Get the hex-encoded commands run during a PSSession
    remote management session (also known as WSMan)
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
