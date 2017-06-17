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
    When listing or dumping scripts, include those run without a path
    Warning: This might drastically increase the number of items returned
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
    https://stackoverflow.com/questions/7760013/why-does-continue-behave-like-break-in-a-foreach-object
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

If ($Credential) {
    $Events = Get-WinEvent -ComputerName $ComputerName -Credential $Credential -FilterHashtable @{
        "ProviderName"="Microsoft-Windows-PowerShell";
        "Id"=4104
    }
}
Else {
    $Events = Get-WinEvent -ComputerName $ComputerName -FilterHashtable @{
        "ProviderName"="Microsoft-Windows-PowerShell";
        "Id"=4104
    }
}

If ($PSCmdlet.ParameterSetName -eq "List") {
    Write-Verbose -Message "Listing all PowerShell scriptblocks run and their last-run times"
    $ScriptLastRunList = @()
    $Events | ForEach-Object {
        $EventXML = [xml]$_.ToXML()
        $ScriptPath = $EventXML.Event.EventData.Data[4].'#text'
        # set the ScriptBlockId as path so the user can correlate it in the event logs if she chooses
        If ($ScriptPath -eq $null) {
            If ($NoName) {
                $ScriptBlockId = $EventXML.Event.EventData.Data[3].'#text'
                $ScriptPath = $ScriptBlockId
            }
            Else {
                return
            }
        }
        If (($ScriptLastRunList).ScriptPath -notcontains $ScriptPath) {
            $NewScript = New-Object psobject
            $NewScript | Add-Member -MemberType NoteProperty -Name "ScriptPath" -Value $ScriptPath
            $NewScript | Add-Member -MemberType NoteProperty -Name "LastRunTime" -Value $_.TimeCreated
            $ScriptLastRunList += $NewScript
        }
    }
    Write-Output -InputObject $ScriptLastRunList
}
ElseIf ($PsCmdlet.ParameterSetName -eq "Script") {
    Write-Verbose -Message "Searching event logs for '$ScriptName'"
    # Since scriptblock text is written in reverse in event logs, need to store it at once
    $TempScriptBlockText = ""
    $Events | ForEach-Object {
        $EventXML = [xml]$_.ToXML()
        $ScriptPath = $EventXML.Event.EventData.Data[4].'#text'
        If ($ScriptPath -eq $null) {
            # ScriptName requires a value in ScriptPath, so we know these can be skipped
            return
        }
        # check if the user's ScriptName input is seen in the path
        If ([string]$ScriptPath.Contains($ScriptName)) {
            $Destination = Join-Path -Path $OutFolder -ChildPath $(Split-Path -Leaf $ScriptPath)
            $MessageNumber = $EventXML.Event.EventData.Data[0].'#text'
            $MessageTotal = $EventXML.Event.EventData.Data[1].'#text'
            $ScriptBlockText = $EventXML.Event.EventData.Data[2].'#text'
            $ScriptBlockId = $EventXML.Event.EventData.Data[3].'#text'
            $ScriptBlockText += $TempScriptBlockText
            If ($MessageNumber -eq 1) {
                Write-Verbose -Message "Writing '$Destination': $MessageTotal sections total"
                Write-Output -InputObject "# Recreated using Get-ScriptBlock.ps1" | Out-File -FilePath $Destination
                Write-Output -InputObject "# ScriptBlockId: $ScriptBlockId" | Out-File -FilePath $Destination -Append
                Write-Output -InputObject $ScriptBlockText | Out-File -FilePath $Destination -Append
                $TempScriptBlockText = ""
            }
        }
    }
}
ElseIf ($PsCmdlet.ParameterSetName -eq "Dump") {
    Write-Verbose -Message "Dumping out all unique PowerShell scripts from event logs"
    # Since scriptblock text is written in reverse in event logs, need to store it at once
    $TempScriptBlockText = ""
    $Events | ForEach-Object {
        $EventXML = [xml]$_.ToXML()
        $MessageNumber = $EventXML.Event.EventData.Data[0].'#text'
        $ScriptBlockId = $EventXML.Event.EventData.Data[3].'#text'
        $ScriptPath = $EventXML.Event.EventData.Data[4].'#text'
        If ($ScriptPath -eq $null) {
            If ($NoName) {
                # If no scriptpath exists, write it out using the block id to keep each unique
                $ScriptPath = "$ScriptBlockId.ps1"
            }
            Else {
                # Assume the user doesn't want to see null-path scripts by default
                return
            }
        }
        $Destination = Join-Path -Path $OutFolder -ChildPath $(Split-Path -Leaf $ScriptPath)
        $ScriptBlockText = $EventXML.Event.EventData.Data[2].'#text'
        $ScriptBlockText += $TempScriptBlockText
        $TempScriptBlockText = $ScriptBlockText
        If ($MessageNumber -eq 1) {
            $MessageTotal = $EventXML.Event.EventData.Data[1].'#text'
            Write-Verbose -Message "Writing '$Destination': $MessageTotal sections total"
            Write-Output -InputObject "# Recreated using Get-ScriptBlock.ps1" | Out-File -FilePath $Destination
            Write-Output -InputObject "# ScriptBlockId: $ScriptBlockId" | Out-File -FilePath $Destination -Append
            Write-Output -InputObject "# Total Sections: $MessageTotal" | Out-File -FilePath $Destination -Append
            Write-Output -InputObject $ScriptBlockText | Out-File -FilePath $Destination -Append
            $TempScriptBlockText = ""
        }
    }
}