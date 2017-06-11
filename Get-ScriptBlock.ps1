<#
    Grab all
#>
[CmdletBinding(DefaultParameterSetName="List")]

Param(
    [Parameter(ParameterSetName="List")]
    [switch]$List,
    [Parameter()]
    [string]$ComputerName = ".",
    [Parameter()]
    [PSCredential]$Credential,
    [Parameter(ParameterSetName="Script", ValueFromPipeline=$true)]
    [string]$ScriptName,
    [Parameter(ParameterSetName="Script")]
    [string]$OutFolder = "$env:USERPROFILE\Downloads"
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
