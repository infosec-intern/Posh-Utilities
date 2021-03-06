<#
.SYNOPSIS
    Extract scriptblocks held in the PowerShell Applications and Services event log
.DESCRIPTION
    Extract scriptblocks held in the PowerShell Applications and Services event log. This includes everythibg from listing the filepaths and their last run time to dumping out the contents of all scripts contained within the event log. It also isn't just limited to the local computer. Remote scriptblocks can be extracted as well
.PARAMETER ComputerName
    Remote computer to search event logs on. Default is the local computer
.PARAMETER Credential
    PSCredential object to authenticate to a remote computer with
.PARAMETER List
    Grab the paths of all scripts that have been run and the last time they were run
.PARAMETER NoName
    When listing or dumping scripts, include those run without a path. Warning: This might drastically increase the number of items returned
.PARAMETER Dump
    Save the contents of all scripts to a designated folder
.PARAMETER ScriptName
    Save the contents of a particular script to a designated folder. Requires the full name specified including extension
.PARAMETER OutFolder
    Folder to save scripts to. Default is the current one
.PARAMETER Path
    Path to an .evtx file to read
.EXAMPLE
    Get-ScriptBlock

    ScriptPath                                                      LastRunTime
    ----------                                                      -----------
    C:\Users\User\Desktop\Import-EditorCommand.ps1                  6/17/2017 4:15:02 PM
    C:\Users\User\Desktop\PowerShellEditorServices.psm1             6/17/2017 4:14:59 PM
    C:\Users\User\Desktop\Posh-VirusTotal.psm1                      6/17/2017 3:22:30 PM


    Simply running the scripts runs the "List" mode by default, where the named scripts in your logs are displayed alongside the last time each one was run. This output is an array of PSObjects, so you can sort and filter them just like any other collection of objects in PowerShell
.EXAMPLE
    Get-ScriptBlock -List -NoName

    ScriptPath                                                      LastRunTime
    ----------                                                      -----------
    C:\Users\User\Desktop\Import-EditorCommand.ps1                  6/17/2017 4:15:02 PM
    C:\Users\User\Desktop\PowerShellEditorServices.psm1             6/17/2017 4:14:59 PM
    C:\Users\User\Desktop\Posh-VirusTotal.psm1                      6/17/2017 3:22:30 PM
    739a4905-3133-4586-b0c3-29dd9c16f26b                            6/17/2017 10:34:09 AM
    1468efda-bcce-4247-a89b-4a27bb83275b                            6/17/2017 10:34:09 AM
    69159608-5e63-49ac-b45e-0c80a8673026                            6/17/2017 10:34:09 AM
    ed396b5f-5514-40e9-bcea-0eacf6acfc36                            6/17/2017 10:34:09 AM


    Running the script in List mode along with the "NoName" parameter lists any scripts in your logs that don't have a ScriptPath associated with them. These scripts are listed instead by their unique ScriptBlockId, which can then be used to look up their contents directly in the event logs
.EXAMPLE
    Get-ScriptBlock -ScriptName CL_Utility.ps1

    ScriptPath    : C:\WINDOWS\TEMP\SDIAG_b0680a0b-4cad-49d2-a02d-546c3320f157\CL_Utility.ps1
    ScriptName    : CL_Utility.ps1
    LastRunTime   : 8/2/2017 6:37:06 PM
    ScriptBlockId : 52cc0c7e-969d-49ab-baa5-65788b98b044
    MessageTotal  : 1
    Text          : # Copyright © 2008, Microsoft Corporation. All rights reserved.


                    #Common utility functions
                    Import-LocalizedData -BindingVariable localizationString -FileName CL_LocalizationData

                    # Function to get user troubleshooting history
                    function Get-UserTSHistoryPath {
                        return "${env:localappdata}\diagnostics"
                    }

                    [the rest redacted for brevity]

    Search the event logs for a specific script name. The script name must match exactly, no regular expression syntax or substrings allowed (for now :))
.EXAMPLE
    Get-ScriptBlock -Dump | Select lastruntime,messagetotal,scriptblockid,scriptname,text | Format-Table

    LastRunTime           MessageTotal ScriptBlockId                        ScriptName                           Text
    -----------           ------------ -------------                        ----------                           ----
    8/2/2017 10:33:02 PM  1            6929ac3d-786a-4e45-a07a-f617e6bfff77 PowerShellEditorServices.VSCode.psm1 #...
    8/2/2017 10:33:02 PM  1            60eccfae-341f-4c9a-91d4-07384d0a46d8 Import-EditorCommand.ps1             #...
    8/2/2017 10:32:59 PM  1            52cbbadf-0276-4061-8c55-dd5e2bac7fbd PowerShellEditorServices.psm1        #...
    8/2/2017 6:37:06 PM   1            52cc0c7e-969d-49ab-baa5-65788b98b044 CL_Utility.ps1                       # Copyright © 2008, Microsoft Corporation. All rights reserved....

    Dump out all the named PowerShell scripts from the event logs. Any that appear in the default List mode will be passed as objects
    Note: I had to drop the ScriptPath field from the output so it would fit in one screen. However, that field is included in the output
.EXAMPLE
    Get-ScriptBlock -List -Path ..\DeepBlueCLI\evtx\Powershell-Invoke-Obfuscation-many.evtx

    ScriptPath                                                                               LastRunTime
    ----------                                                                               -----------
    C:\Users\student\Desktop\Invoke-Obfuscation-master\Out-SecureStringCommand.ps1           8/30/2017 1:12:09 PM
    C:\Users\student\Desktop\DeepBlueCLI-master\DeepBlue-0.3.ps1                             8/30/2017 1:01:22 PM
    C:\Users\student\Desktop\Invoke-Obfuscation-master\Out-EncodedBinaryCommand.ps1          8/30/2017 12:55:56 PM
    C:\Users\student\Desktop\Invoke-Obfuscation-master\Out-EncodedHexCommand.ps1             8/30/2017 12:22:17 PM

    Read the scriptblocks from a specific .evtx file instead of the computer's
.LINK
    https://github.com/infosec-intern/Posh-Utilities/
    https://blogs.technet.microsoft.com/ashleymcglone/2013/08/28/powershell-get-winevent-xml-madness-getting-details-from-event-logs/
    https://stackoverflow.com/questions/7760013/why-does-continue-behave-like-break-in-a-foreach-object
#>
Function Get-ScriptBlock {
    [CmdletBinding(DefaultParameterSetName="List")]

    Param(
        [Parameter(Mandatory=$false)]
        [string]$ComputerName = "$env:COMPUTERNAME",
        [Parameter(Mandatory=$false)]
        [PSCredential]$Credential,
        [Parameter(Mandatory=$false)]
        [string]$Path,
        [Parameter(ParameterSetName="List", Mandatory=$false)]
        [switch]$List,
        [Parameter(ParameterSetName="List", Mandatory=$false)]
        [Parameter(ParameterSetName="Dump", Mandatory=$false)]
        [switch]$NoName,
        [Parameter(ParameterSetName="Dump", Mandatory=$false)]
        [switch]$Dump,
        [Parameter(ParameterSetName="Script", ValueFromPipeline=$true, Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$ScriptName
    )
    BEGIN {
        $Scripts = @()
        $Filter = @{
            "ProviderName"="Microsoft-Windows-PowerShell";
            "Id"=4104;
        }

        If ($Path) {
            $Filter.Add("Path", $Path)
        }

        If ($Credential) {
            $Events = Get-WinEvent -ComputerName $ComputerName -Credential $Credential -FilterHashtable $Filter
        }
        Else {
            $Events = Get-WinEvent -ComputerName $ComputerName -FilterHashtable $Filter
        }
    }
    PROCESS {
        If ($PSCmdlet.ParameterSetName -eq "List") {
            Write-Verbose -Message "Listing all PowerShell scriptblocks run and their last-run times"
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
                If (($Scripts).ScriptPath -notcontains $ScriptPath) {
                    $NewScript = New-Object psobject
                    $NewScript | Add-Member -MemberType NoteProperty -Name "ScriptPath" -Value $ScriptPath
                    $NewScript | Add-Member -MemberType NoteProperty -Name "LastRunTime" -Value $_.TimeCreated
                    $Scripts += $NewScript
                }
            }
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
                    $MessageNumber = $EventXML.Event.EventData.Data[0].'#text'
                    $ScriptBlockText = $EventXML.Event.EventData.Data[2].'#text'
                    $ScriptBlockText += $TempScriptBlockText
                    $TempScriptBlockText = $ScriptBlockText
                    If ($MessageNumber -eq 1) {
                        $MessageTotal = $EventXML.Event.EventData.Data[1].'#text'
                        $ScriptBlockId = $EventXML.Event.EventData.Data[3].'#text'
                        # Completely break out of the ForEach-Object pipeline when the script has been found
                        $NewScript = New-Object psobject
                        $NewScript | Add-Member -MemberType NoteProperty -Name "ScriptPath" -Value $ScriptPath
                        $NewScript | Add-Member -MemberType NoteProperty -Name "ScriptName" -Value $(Split-Path -Leaf $ScriptPath)
                        $NewScript | Add-Member -MemberType NoteProperty -Name "LastRunTime" -Value $_.TimeCreated
                        $NewScript | Add-Member -MemberType NoteProperty -Name "ScriptBlockId" -Value $ScriptBlockId
                        $NewScript | Add-Member -MemberType NoteProperty -Name "MessageTotal" -Value $MessageTotal
                        $NewScript | Add-Member -MemberType NoteProperty -Name "Text" -Value $ScriptBlockText
                        $Scripts += $NewScript
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
                $ScriptBlockText = $EventXML.Event.EventData.Data[2].'#text'
                $ScriptBlockText += $TempScriptBlockText
                $TempScriptBlockText = $ScriptBlockText
                If ($MessageNumber -eq 1) {
                    $MessageTotal = $EventXML.Event.EventData.Data[1].'#text'
                    $NewScript = New-Object psobject
                    $NewScript | Add-Member -MemberType NoteProperty -Name "ScriptPath" -Value $ScriptPath
                    $NewScript | Add-Member -MemberType NoteProperty -Name "ScriptName" -Value $(Split-Path -Leaf $ScriptPath)
                    $NewScript | Add-Member -MemberType NoteProperty -Name "LastRunTime" -Value $_.TimeCreated
                    $NewScript | Add-Member -MemberType NoteProperty -Name "ScriptBlockId" -Value $ScriptBlockId
                    $NewScript | Add-Member -MemberType NoteProperty -Name "MessageTotal" -Value $MessageTotal
                    $NewScript | Add-Member -MemberType NoteProperty -Name "Text" -Value $ScriptBlockText
                    $Scripts += $NewScript
                    $TempScriptBlockText = ""
                }
            }
        }
    }
    END {
        Write-Output -InputObject $Scripts
    }
}