<#
.SYNOPSIS
    Extract scriptblocks held in the PowerShell Applications and Services event log
.DESCRIPTION
    Extract scriptblocks held in the PowerShell Applications and Services event log.
    This includes everythibg from listing the filepaths and their last run time to dumping out the contents of all scripts
    contained within the event log. It also isn't just limited to the local computer. Remote scriptblocks can be extracted as well
.PARAMETER ComputerName
    Remote computer to search event logs on. Default is the local computer
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
.LINK
    https://github.com/infosec-intern/Posh-Utilities/blob/master/Get-ScriptBlock.ps1
    https://blogs.technet.microsoft.com/ashleymcglone/2013/08/28/powershell-get-winevent-xml-madness-getting-details-from-event-logs/
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

$Events = Get-WinEvent -FilterHashtable @{
    "ProviderName"="Microsoft-Windows-PowerShell";
    "Id"=4104
}

If ($PSCmdlet.ParameterSetName -eq "List") {
    $ScriptLastRunList = @()
    $Events | ForEach-Object {
        $EventXML = [xml]$_.ToXML()
        $ScriptPath = $EventXML.Event.EventData.Data[4].'#text'
        If (($ScriptPath -ne $null) -and (($ScriptLastRunList).ScriptPath -notcontains $ScriptPath)) {
            $NewScript = New-Object psobject
            $NewScript | Add-Member -MemberType NoteProperty -Name "ScriptPath" -Value $ScriptPath
            $NewScript | Add-Member -MemberType NoteProperty -Name "LastRunTime" -Value $_.TimeCreated
            Write-Verbose "Adding $ScriptPath to list"
            $ScriptLastRunList += $NewScript
        }
    }
    Write-Output $ScriptLastRunList
}
ElseIf ($PsCmdlet.ParameterSetName -eq "Script") {
    $CurrentScriptId = 0
    $Events | ForEach-Object {
        $EventXML = [xml]$_.ToXML()
        $ScriptBlockId = $EventXML.Event.EventData.Data[3].'#text'
        $ScriptPath = $EventXML.Event.EventData.Data[4].'#text'
        # check if the user's ScriptName input is seen in the path
        If ($ScriptName -iin $ScriptPath) {
            $Destination = Join-Path -Path $OutFolder -ChildPath $ScriptName
            $ScriptBlockText = $EventXML.Event.EventData.Data[2].'#text'
            If ($CurrentScriptId -eq 0) {
                # Set the CurrentScriptId and only allow it to be modified this one time
                Set-Variable -Name $CurrentScriptId -Value $EventXML.Event.EventData.Data[3].'#text' -Option ReadOnly
                Write-Output "# Recreated using Get-ScriptBlock.ps1" | Out-File -FilePath $Destination
                Write-Output $ScriptBlockText | Out-File -FilePath $Destination -Append
            }
            ElseIf ($CurrentScriptId -eq $ScriptBlockId) {
                Write-Output $ScriptBlockText | Out-File -FilePath $Destination -Append
            }
        }
    }
}
ElseIf ($PsCmdlet.ParameterSetName -eq "Dump") {
    $CurrentScriptId = 0
    $Events | ForEach-Object {
        $EventXML = [xml]$_.ToXML()
        $MessageNumber = $EventXML.Event.EventData.Data[0].'#text'
        $MessageTotal = $EventXML.Event.EventData.Data[1].'#text'
        $ScriptBlockText = $EventXML.Event.EventData.Data[2].'#text'
        $ScriptBlockId = $EventXML.Event.EventData.Data[3].'#text'
        $ScriptPath = $EventXML.Event.EventData.Data[4].'#text'
        If ($ScriptBlockId -ne $CurrentScriptId) {
            $CurrentScriptId = $ScriptBlockId
        }
        If ($ScriptPath -eq $null) {
            # If no scriptpath exists, write it out using the block id
            $ScriptPath = "$ScriptBlockId.ps1"
        }
        $Destination = Join-Path -Path $OutFolder -ChildPath $(Split-Path -Leaf $ScriptPath)
        Write-Output "# Recreated using Get-ScriptBlock.ps1" | Out-File -FilePath $Destination
        Write-Verbose -Message "Writing '$Destination' ($MessageNumber/$MessageTotal)"
        Write-Output $ScriptBlockText | Out-File -FilePath $Destination -Append
    }
}