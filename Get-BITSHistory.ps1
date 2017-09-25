<#
.SYNOPSIS
    Analyze event logs for information about previous Background Intelligent Transfer sessions (also known as BITS)
.DESCRIPTION
    Analyze event logs for information about previous Background Intelligent Transfer sessions (also known as BITS). This includes when sessions are started and stopped, and the URLs they were reaching out to. This is separate from the Get-BITSTransfer cmdlet, which only details current BITS sessions
.PARAMETER ComputerName
    Remote computer to search event logs on. Default is the local computer
.PARAMETER Credential
    PSCredential object to authenticate to a remote computer with
.PARAMETER Path
    Path to an event log (should end in .evtx) to read
.PARAMETER List
    List the BITS sessions and their actions (cancelled, completed, ongoing, etc.)
.EXAMPLE
    Get-BITSHistory
.EXAMPLE
    Get-BITSHistory -Path "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Bits-Client%4Operational.evtx"
.LINK
    https://github.com/infosec-intern/Posh-Utilities/
    Advanced Functions: https://technet.microsoft.com/en-us/library/hh413265.aspx
.NOTES
    Event ID 3:
        The BITS service created a new job.
        Transfer job: Push Notification Platform Job: 1
        Job ID: {b652f1e5-5a4f-4a3c-9673-21b527e3b142}
        Owner: computer\Username
        Process Path: C:\Windows\System32\svchost.exe
        Process ID: 3388
    Event ID 4:
        The transfer job is complete.
        User: computer\Username
        Transfer job: Push Notification Platform Job: 1
        Job ID: {b0bd0c0e-7724-49e2-a627-7b9faaa32316}
        Owner: computer\Username
        File count: 1
    Event ID 5:
        Job cancelled.
        User: NT AUTHORITY\NETWORK SERVICE
        job: MicrosoftMapsBingGeoStore
        jobID: {8636eee8-dc04-472e-aa33-60838f7a4232}
        owner: NT AUTHORITY\NETWORK SERVICE
        filecount: 0
    Event ID 59:
        BITS started the Push Notification Platform Job: 1 transfer job that is associated with the http://google.com/ URL.
    Event ID 60:
        BITS stopped transferring the Push Notification Platform Job: 1 transfer job that is associated with the http://google.com/ URL. The status code is 0x0.
    Event ID 61: (appears to be exclusively for jobs that ended early)
        BITS stopped transferring the Push Notification Platform Job: 1 transfer job that is associated with the http://google.com/ URL. The status code is 0x80072EE7.
#>
Function Get-BITSHistory {
    [CmdletBinding(DefaultParameterSetName="List")]
    Param(
        [Parameter()]
        [string]$ComputerName = "$env:COMPUTERNAME",
        [Parameter()]
        [PSCredential]$Credential,
        [Parameter()]
        [string]$Path,
        [Parameter(ParameterSetName="List")]
        [switch]$List
    )
    BEGIN {
        # set up allthethings
        $Jobs = @{}
        $ProviderName = "Microsoft-Windows-Bits-Client"
        $LogName = "Microsoft-Windows-Bits-Client/Operational"

        $Filter = @{
            "ProviderName"=$ProviderName;
            "LogName"=$LogName;
            "Id"=3,4,5,59,60,61;
        }

        If ($Path) {
            $Filter.Add("Path", $Path)
        }

        If ($Credential) {
            $Events = Get-WinEvent -Oldest -ComputerName $ComputerName -Credential $Credential -FilterHashtable $Filter
        }
        Else {
            $Events = Get-WinEvent -Oldest -ComputerName $ComputerName -FilterHashtable $Filter
        }
    }
    PROCESS {
        ForEach ($Event in $Events) {
            $Record = ([xml]$Event.ToXML()).Event.EventData.Data
            switch ($Event.Id) {
                3 {
                    Write-Verbose "Parsing StartJob -EventLog $($Event.Id)"
                    $JobId = $Record[1].'#text'
                    $Jobs[$JobId] = New-Object -TypeName PSObject -Property @{
                        "Name" = $Record[0].'#text';
                        "Id" = $JobId;
                        "Owner" = $Record[2].'#text';
                        "ProcessPath" = $Record[3].'#text';
                        "ProcessId" = $Record[4].'#text';
                        "StartTime" = $Event.TimeCreated
                    }
                }
                4 {
                    Write-Verbose "Parsing CompletedJob -EventLog $($Event.Id)"
                    If ($Jobs.Count -le 0) { break }
                }
                5 {
                    Write-Verbose "Parsing CancelledJob -EventLog $($Event.Id)"
                    If ($Jobs.Count -le 0) { break }
                }
                59 {
                    Write-Verbose "Parsing StartURL -EventLog $($Event.Id)"
                    $JobId = $Record[2].'#text'
                    If ($Jobs.Count -le 0) {
                        # if we encounter this situation it means the event logs rolled off in the middle of a BITS job
                        # we need to create a minimalist job and fill in what we know
                        $Jobs[$JobId] = New-Object -TypeName PSObject -Property @{
                            "Name" = $Record[1].'#text';
                            "Id" = $JobId;
                            "Owner" = "???";
                            "ProcessPath" = "???";
                            "ProcessId" = "???";
                            "StartTime" = "???";
                        }
                    }
                    $Jobs[$JobId] | Add-Member -MemberType NoteProperty -Name "URL" -Value $Record[3].'#text' -Force -ErrorAction SilentlyContinue
                    $Jobs[$JobId] | Add-Member -MemberType NoteProperty -Name "BytesTotal" -Value $Record[7].'#text' -Force -ErrorAction SilentlyContinue
                }
                60 {
                    Write-Verbose "Parsing StopURL -EventLog $($Event.Id)"
                    If ($Jobs.Count -le 0) { break }
                }
                61 {
                    Write-Verbose "Parsing ErrorURL -EventLog $($Event.Id)"
                    If ($Jobs.Count -le 0) { break }
                }
                Default {
                    $Result = "I can't parse event ID $($Event.Id)"
                }
            }
        }
    }
    END {
        # display back to the user in the form requested
        Write-Output $Jobs.Values
    }
}