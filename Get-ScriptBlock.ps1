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
    Save the contents of a particular script to a designated folder. Requires the full name specified including extension
.PARAMETER OutFolder
    Folder to save scripts to. Default is the current one
.EXAMPLE
    .\Get-ScriptBlock.ps1

    ScriptPath                                                                                          LastRunTime
    ----------                                                                                          -----------
    C:\Users\User\Desktop\Import-EditorCommand.ps1                                                      6/17/2017 4:15:02 PM
    C:\Users\User\Desktop\PowerShellEditorServices.psm1                                                 6/17/2017 4:14:59 PM
    C:\Users\User\Desktop\Posh-VirusTotal.psm1                                                          6/17/2017 3:22:30 PM


    Simply running the scripts runs the "List" mode by default, where the named scripts in your logs are displayed
    alongside the last time each one was run. This output is an array of PSObjects, so you can sort and filter them just
    like any other collection of objects in PowerShell
.EXAMPLE
    .\Get-ScriptBlock.ps1 -List -NoName

    ScriptPath                                                      LastRunTime
    ----------                                                      -----------
    C:\Users\User\Desktop\Import-EditorCommand.ps1                  6/17/2017 4:15:02 PM
    C:\Users\User\Desktop\PowerShellEditorServices.psm1             6/17/2017 4:14:59 PM
    C:\Users\User\Desktop\Posh-VirusTotal.psm1                      6/17/2017 3:22:30 PM
    739a4905-3133-4586-b0c3-29dd9c16f26b                            6/17/2017 10:34:09 AM
    1468efda-bcce-4247-a89b-4a27bb83275b                            6/17/2017 10:34:09 AM
    69159608-5e63-49ac-b45e-0c80a8673026                            6/17/2017 10:34:09 AM
    ed396b5f-5514-40e9-bcea-0eacf6acfc36                            6/17/2017 10:34:09 AM


    Running the script in List mode along with the "NoName" parameter lists any scripts in your logs that don't have a ScriptPath
    associated with them. These scripts are listed instead by their unique ScriptBlockId, which can then be used to look up their
    contents directly in the event logs
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
    [string]$OutFolder = "$(Convert-Path -Path .)"
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
    # Since scriptblock text is written in reverse in event logs, need to store blocks at once then write them out at the end
    $TempScriptBlockText = ""
    $Events | ForEach-Object {
        $EventXML = [xml]$_.ToXML()
        $ScriptPath = $EventXML.Event.EventData.Data[4].'#text'
        If ($ScriptPath -eq $null) {
            # ScriptName requires a value in ScriptPath, so we know these empty ones can be skipped
            return
        }
        If ($(Split-Path -Leaf $ScriptPath) -eq $ScriptName) {
            $Destination = Join-Path -Path $OutFolder -ChildPath $(Split-Path -Leaf $ScriptPath)
            $MessageNumber = $EventXML.Event.EventData.Data[0].'#text'
            $ScriptBlockText = $EventXML.Event.EventData.Data[2].'#text'
            $ScriptBlockText += $TempScriptBlockText
            $TempScriptBlockText = $ScriptBlockText
            If ($MessageNumber -eq 1) {
                Write-Verbose -Message "Writing '$Destination'"
                $MessageTotal = $EventXML.Event.EventData.Data[1].'#text'
                $ScriptBlockId = $EventXML.Event.EventData.Data[3].'#text'
                Write-Output -InputObject "# Recreated using Get-ScriptBlock.ps1" | Out-File -FilePath $Destination
                Write-Output -InputObject "# ScriptBlockId: $ScriptBlockId" | Out-File -FilePath $Destination -Append
                Write-Output -InputObject "# Total Sections: $MessageTotal" | Out-File -FilePath $Destination -Append
                Write-Output -InputObject $ScriptBlockText | Out-File -FilePath $Destination -Append
                # Completely break out of the ForEach-Object pipeline when the script has been found
                continue
            }
        }
    }
}
ElseIf ($PsCmdlet.ParameterSetName -eq "Dump") {
    Write-Verbose -Message "Dumping out all unique PowerShell scripts from event logs"
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
        If (Test-Path -Path $Destination) {
            return
        }
        $ScriptBlockText = $EventXML.Event.EventData.Data[2].'#text'
        $ScriptBlockText += $TempScriptBlockText
        $TempScriptBlockText = $ScriptBlockText
        If ($MessageNumber -eq 1) {
            $MessageTotal = $EventXML.Event.EventData.Data[1].'#text'
            Write-Verbose -Message "Writing '$Destination': $MessageTotal sections"
            Write-Output -InputObject "# Recreated using Get-ScriptBlock.ps1" | Out-File -FilePath $Destination
            Write-Output -InputObject "# ScriptBlockId: $ScriptBlockId" | Out-File -FilePath $Destination -Append
            Write-Output -InputObject "# Total Sections: $MessageTotal" | Out-File -FilePath $Destination -Append
            Write-Output -InputObject $ScriptBlockText | Out-File -FilePath $Destination -Append
            $TempScriptBlockText = ""
        }
    }
}