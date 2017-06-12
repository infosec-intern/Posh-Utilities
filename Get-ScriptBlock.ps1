<#
.SYNOPSIS

.DESCRIPTION
.PARAMETER ComputerName
    Remote computer to search event logs on. Default is the local machine
.PARAMETER Credential
    PSCredential object to authenticate to a remote computer with
.PARAMETER List
    Grab the paths of all scripts that have been run and the last time they were run
.PARAMETER Dump
    Save the contents of all scripts to a designated folder
.PARAMETER ScriptName
    Save the contents of a particular script to a designated folder
.PARAMETER OutFolder
    Particular folder to save scripts to. Default is the current one
.EXAMPLE
#>
[CmdletBinding(DefaultParameterSetName="List")]

Param(
    [Parameter()]
    [string]$ComputerName = ".",
    [Parameter()]
    [PSCredential]$Credential,
    [Parameter(ParameterSetName="List")]
    [switch]$List,
    [Parameter(ParameterSetName="Dump")]
    [switch]$Dump,
    [Parameter(ParameterSetName="Script", ValueFromPipeline=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$ScriptName,
    [Parameter(ParameterSetName="Dump")]
    [Parameter(ParameterSetName="Script")]
    [ValidateNotNullOrEmpty()]
    [string]$OutFolder = "$env:USERPROFILE\Desktop"
)

$Events = Get-WinEvent -MaxEvents 1 -FilterHashtable @{
    "ProviderName"="Microsoft-Windows-PowerShell";
    "Id"=4104
}

$CurrentScript = 0

$Events | ForEach-Object {
    # gathered from https://blogs.technet.microsoft.com/ashleymcglone/2013/08/28/powershell-get-winevent-xml-madness-getting-details-from-event-logs/
    $EventXML = [xml]$_.ToXML()
    $MessageNumber = $EventXML.Event.EventData.Data[0].'#text'
    $MessageTotal = $EventXML.Event.EventData.Data[1].'#text'
    $ScriptBlockText = $EventXML.Event.EventData.Data[2].'#text'
    $ScriptBlockId = $EventXML.Event.EventData.Data[3].'#text'
    $ScriptPath = $EventXML.Event.EventData.Data[4].'#text'

    # If "Script" ParameterSetName and a script to search for are set, then only write out that script if it exists
    If ($PsCmdlet.ParameterSetName -eq "Script") {
    }
    # If ParameterSetName isn't "Script", then assume it's "List" and write out all scripts
    Else {
        If ($ScriptBlockId -ne $CurrentScript) {
            $CurrentScript = $ScriptBlockId
        }
        If ($ScriptPath -eq $null) {
            # If no scriptpath exists, write it out using the block id
            $ScriptPath = "$ScriptBlockId.ps1"
        }
        Write-Verbose -Message "Writing '$OutFolder\$(Split-Path -Leaf $ScriptPath)' ($MessageNumber/$MessageTotal)"
        $ScriptBlockText | Out-File -FilePath "$OutFolder\$(Split-Path -Leaf $ScriptPath)" -Append
    }
}
