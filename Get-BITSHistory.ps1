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
    (Get-BITSHistory | Measure-Object).Count

    200


    Count the number of BITS jobs that have been logged by the Windows Event Log

.EXAMPLE
    Get-BITSHistory -Path "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Bits-Client%4Operational.evtx" | Select-Object -First 1

    Id              : {2ABEF5DC-81A6-49F0-B314-D324D31A75D1}
    Name            : Push Notification Platform Job: 1
    Owner           : computer\Username
    ProcessPath     : C:\Windows\System32\svchost.exe
    StartTime       : 9/16/2017 4:25:47 PM
    ProcessId       : 1964
    URL             : http://img-s-msn-com.akamaized.net/tenant/amp/entityid/AArXcnF.img?w=204&h=100&m=6&tilesize=wide&x=620&y=148&ms-scale=150&ms-contrast=standard
    BytesTotal      : 15552
    StatusCode      : 0
    ByteTransferred : 15552
    EndTime         : 9/16/2017 4:25:47 PM


    Print the first BITS job in the specified .evtx file
    **Note**: Due to the way PowerShell pipelining works, this still parses all BITS jobs out first

.EXAMPLE
    Get-BITSHistory | Where-Object { $_.StatusCode -ne 0 } | Select-Object Owner,ProcessPath,StartTime,EndTime,StatusCode | Format-Table

    Owner                        ProcessPath                                                 StartTime             EndTime               StatusCode
    -----                        -----------                                                 ---------             -------               ----------
    NT AUTHORITY\NETWORK SERVICE C:\Windows\System32\svchost.exe                             9/8/2017 1:48:29 AM   9/8/2017 1:48:29 AM
    computer\Username            C:\Windows\System32\svchost.exe                             9/15/2017 9:13:30 PM  9/15/2017 9:13:30 PM  2147954407
    computer\Username            C:\Program Files (x86)\Google\Chrome\Application\chrome.exe 9/17/2017 12:01:10 PM 9/17/2017 3:18:01 PM  262152
    computer\Username            C:\Windows\System32\svchost.exe                             9/15/2017 9:13:26 PM  9/15/2017 9:13:26 PM  2147954407
    NT AUTHORITY\SYSTEM          C:\Program Files (x86)\Google\Update\GoogleUpdate.exe       9/12/2017 8:45:18 PM  9/12/2017 8:45:18 PM  2147954407


    Get the BITS jobs that ended with an error

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
                        "StartTime" = $Event.TimeCreated;
                    }
                }
                4 {
                    Write-Verbose "Parsing CompletedJob -EventLog $($Event.Id)"
                    $JobId = $Record[2].'#text'
                    If ($Jobs.Count -le 0) { break }
                    $Jobs[$JobId] | Add-Member -MemberType NoteProperty -Name "ByteTransferred" -Value $Record[5].'#text' -Force -ErrorAction SilentlyContinue
                    $Jobs[$JobId] | Add-Member -MemberType NoteProperty -Name "EndTime" -Value $Event.TimeCreated -Force -ErrorAction SilentlyContinue
                }
                5 {
                    Write-Verbose "Parsing CancelledJob -EventLog $($Event.Id)"
                    $JobId = $Record[2].'#text'
                    If ($Jobs.Count -le 0) {
                        $Jobs[$JobId] = New-Object -TypeName PSObject -Property @{
                            "Name" = $Record[1].'#text';
                            "Id" = $JobId;
                            "Owner" = $Record[3].'#text';
                        }
                    }
                    $Jobs[$JobId] | Add-Member -MemberType NoteProperty -Name "EndTime" -Value $Event.TimeCreated -Force -ErrorAction SilentlyContinue
                    $Jobs[$JobId] | Add-Member -MemberType NoteProperty -Name "User" -Value $Record[0].'#text' -Force -ErrorAction SilentlyContinue
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
                        }
                    }
                    $Jobs[$JobId] | Add-Member -MemberType NoteProperty -Name "URL" -Value $Record[3].'#text' -Force -ErrorAction SilentlyContinue
                    $Jobs[$JobId] | Add-Member -MemberType NoteProperty -Name "BytesTotal" -Value $Record[7].'#text' -Force -ErrorAction SilentlyContinue
                }
                60 {
                    Write-Verbose "Parsing StopURL -EventLog $($Event.Id)"
                    $JobId = $Record[2].'#text'
                    If ($Jobs.Count -le 0) {
                        $Jobs[$JobId] = New-Object -TypeName PSObject -Property @{
                            "Name" = $Record[1].'#text';
                            "Id" = $JobId;
                        }
                    }
                    $Jobs[$JobId] | Add-Member -MemberType NoteProperty -Name "BytesTotal" -Value $Record[7].'#text' -Force -ErrorAction SilentlyContinue
                    $Jobs[$JobId] | Add-Member -MemberType NoteProperty -Name "StatusCode" -Value $Record[5].'#text' -Force -ErrorAction SilentlyContinue
                    $Jobs[$JobId] | Add-Member -MemberType NoteProperty -Name "EndTime" -Value $Event.TimeCreated -Force -ErrorAction SilentlyContinue
                }
                61 {
                    Write-Verbose "Parsing ErrorURL -EventLog $($Event.Id)"
                    $JobId = $Record[2].'#text'
                    If ($Jobs.Count -le 0) {
                        $Jobs[$JobId] = New-Object -TypeName PSObject -Property @{
                            "Name" = $Record[1].'#text';
                            "Id" = $JobId;
                        }
                    }
                    # Can't add any file properties..fileTime is MS Epoch, fileLength and fileTotal are 0xFFFFFFFFFFFFFFFF
                    $Jobs[$JobId] | Add-Member -MemberType NoteProperty -Name "StatusCode" -Value $Record[5].'#text' -Force -ErrorAction SilentlyContinue
                    $Jobs[$JobId] | Add-Member -MemberType NoteProperty -Name "EndTime" -Value $Event.TimeCreated -Force -ErrorAction SilentlyContinue
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