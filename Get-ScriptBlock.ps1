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
.PARAMETER NoName
    When listing scripts, include those run without a path
    Warning: This might drastically increase the number returned
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
    [string]$ComputerName = "$env:COMPUTERNAME",
    [Parameter()]
    [PSCredential]$Credential,
    [Parameter(ParameterSetName="List")]
    [switch]$List,
    [Parameter(ParameterSetName="List")]
    [Parameter(ParameterSetName="Dump")]
    [switch]$NoName,
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

$Events = Get-WinEvent -ComputerName $ComputerName -FilterHashtable @{
    "ProviderName"="Microsoft-Windows-PowerShell";
    "Id"=4104
}

If ($PSCmdlet.ParameterSetName -eq "List") {
    Write-Verbose -Message "Listing all PowerShell scriptblocks run and their last-run times"
    $ScriptLastRunList = @()
    $Events | ForEach-Object {
        $EventXML = [xml]$_.ToXML()
        $ScriptPath = $EventXML.Event.EventData.Data[4].'#text'
        # set the ScriptBlockId as path so the user can correlate it in the event logs if she chooses
        If (($ScriptPath -eq $null) -and ($NoName)) {
            $ScriptBlockId = $EventXML.Event.EventData.Data[3].'#text'
            $ScriptPath = $ScriptBlockId
        }
        If (($ScriptLastRunList).ScriptPath -notcontains $ScriptPath) {
            $NewScript = New-Object psobject
            $NewScript | Add-Member -MemberType NoteProperty -Name "ScriptPath" -Value $ScriptPath
            $NewScript | Add-Member -MemberType NoteProperty -Name "LastRunTime" -Value $_.TimeCreated
            Write-Debug -Message "Adding $ScriptPath to list"
            $ScriptLastRunList += $NewScript
        }
    }
    Write-Output -InputObject $ScriptLastRunList
}
ElseIf ($PsCmdlet.ParameterSetName -eq "Script") {
    Write-Verbose -Message "Searching event logs for '$ScriptName'"
    $Events | ForEach-Object {
        $EventXML = [xml]$_.ToXML()
        $MessageNumber = $EventXML.Event.EventData.Data[0].'#text'
        $MessageTotal = $EventXML.Event.EventData.Data[1].'#text'
        $ScriptBlockId = $EventXML.Event.EventData.Data[3].'#text'
        $ScriptPath = $EventXML.Event.EventData.Data[4].'#text'
        $Destination = Join-Path -Path $OutFolder -ChildPath $ScriptName
        # if the destination file already exists, don't write it out
        If (Test-Path -Path $Destination) {
            Write-Debug -Message "'$Destination' already exists. Skipping ($MessageNumber/$MessageTotal)"
            continue
        }
        # check if the user's ScriptName input is seen in the path
        If ($ScriptName -iin $ScriptPath) {
            Write-Debug -Message "Writing '$Destination' ($MessageNumber/$MessageTotal)"
            $ScriptBlockText = $EventXML.Event.EventData.Data[2].'#text'
            If ($MessageNumber -eq 1) {
                Write-Output -InputObject "# Recreated using Get-ScriptBlock.ps1" | Out-File -FilePath $Destination
                Write-Output -InputObject "# ScriptBlockId: $ScriptBlockId" | Out-File -FilePath $Destination -Append
                Write-Output -InputObject $ScriptBlockText | Out-File -FilePath $Destination -Append
            }
            Else {
                Write-Output -InputObject $ScriptBlockText | Out-File -FilePath $Destination -Append
            }
        }
    }
}
ElseIf ($PsCmdlet.ParameterSetName -eq "Dump") {
    Write-Verbose -Message "Dumping out all unique PowerShell scripts from event logs"
    $Events | ForEach-Object {
        $EventXML = [xml]$_.ToXML()
        $MessageNumber = $EventXML.Event.EventData.Data[0].'#text'
        $MessageTotal = $EventXML.Event.EventData.Data[1].'#text'
        $ScriptBlockText = $EventXML.Event.EventData.Data[2].'#text'
        $ScriptPath = $EventXML.Event.EventData.Data[4].'#text'
        If ($ScriptPath -eq $null) {
            Write-Verbose -Message "ScriptPath is null"
            If ($NoName) {
                Write-Debug -Message "ScriptPath is null and NoName is specified. Changing path to $ScriptBlockId"
                # If no scriptpath exists, write it out using the block id
                $ScriptBlockId = $EventXML.Event.EventData.Data[3].'#text'
                $ScriptPath = "$ScriptBlockId.ps1"
            }
            Else {
                # if ScriptPath is null and -NoName isn't specified, assume the user doesn't want to see this script
                continue
            }
        }
        Write-Verbose -Message "Writing '$Destination' ($MessageNumber/$MessageTotal)"
        $Destination = Join-Path -Path $OutFolder -ChildPath $(Split-Path -Leaf $ScriptPath)
        Write-Output -InputObject "# Recreated using Get-ScriptBlock.ps1" | Out-File -FilePath $Destination
        Write-Output -InputObject $ScriptBlockText | Out-File -FilePath $Destination -Append
    }
}