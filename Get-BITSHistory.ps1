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
        $ProviderName = "Microsoft-Windows-Bits-Client"
        $LogName = "Microsoft-Windows-Bits-Client/Operational"

        $Filter = @{
            "ProviderName"=$ProviderName;
            "LogName"=$LogName;
            "Id"=3#,4,5,59,60,61;
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
        $Results = @()
        ForEach ($Event in $Events) {
            switch ($Event.Id) {
                3 {
                    Write-Verbose "Parseing StartJob -EventLog $($Event.Id)"
                    $Lines = $Event.Message.Split("`r`n")
                    $Result = New-Object -TypeName PSObject -Property @{
                        "TransferJob" = $Lines[2].Replace("Transfer job: ", "");
                        "JobId" = $Lines[4].Replace("Job ID: ", "");
                        "Owner" = $Lines[6].Replace("Owner: ", "");
                        "ProcessPath" = $Lines[8].Replace("Process Path: ", "");
                        "ProcessId" = $Lines[10].Replace("Process ID: ", "");
                    }
                }
                4 {
                    Write-Verbose "Parseing CompletedJob -EventLog $($Event.Id)"
                }
                5 {
                    Write-Verbose "Parseing CancelledJob -EventLog $($Event.Id)"
                }
                59 {
                    Write-Verbose "Parseing StartURL -EventLog $($Event.Id)"
                }
                60 {
                    Write-Verbose "Parseing StopURL -EventLog $($Event.Id)"
                }
                61 {
                    Write-Verbose "Parseing ErrorURL -EventLog $($Event.Id)"
                }
                Default {
                    $Result = "I can't parse event ID $($Event.Id)"
                }
            }
            $Results += $Result
        }
    }
    END {
        # display back to the user in the form requested
        Write-Output $Results
    }
}