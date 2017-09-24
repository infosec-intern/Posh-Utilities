<#
.SYNOPSIS
    Analyze event logs for information about previous Background Intelligent Transfer sessions (also known as BITS)
.DESCRIPTION
    Analyze event logs for information about previous Background Intelligent Transfer sessions (also known as BITS). This includes when sessions are started and stopped, and the URLs they were reaching out to. This is separate from the Get-BITSTransfer cmdlet, which only details current BITS sessions
.PARAMETER ComputerName
    Remote computer to search event logs on. Default is the local computer
.PARAMETER Credential
    PSCredential object to authenticate to a remote computer with
.PARAMETER List
    List the BITS sessions and their actions (cancelled, completed, ongoing, etc.)
.EXAMPLE
    .\Get-BITSHistory.ps1
.LINK
    https://github.com/infosec-intern/Posh-Utilities/
#>
[CmdletBinding(DefaultParameterSetName="List")]

Param(
    [Parameter()]
    [string]$ComputerName = "$env:COMPUTERNAME",
    [Parameter()]
    [PSCredential]$Credential,
    [Parameter(ParameterSetName="List")]
    [switch]$List
)

<#
.SYNOPSIS
    Parse out data from the "created new job" log records
.DESCRIPTION
    Parse out the job name, job GUID, owner, process path and ID of BITS events with ID 3
    Returns a PSCustomObject containing all the data, with attributes matching the event records
.PARAMETER EventLog
    An individual record from an event log. The only acceptable Event ID for this function is 3
    Anything else will return no data
.EXAMPLE
    Parse-StartJob -EventLog $record
.NOTES
    The BITS service created a new job.
    Transfer job: Push Notification Platform Job: 1
    Job ID: {b652f1e5-5a4f-4a3c-9673-21b527e3b142}
    Owner: computer\Username
    Process Path: C:\Windows\System32\svchost.exe
    Process ID: 3388
#>
Function Parse-StartJob {
    Param(
        [EventLogRecord]$EventLog
    )
    [PSCustomObject]$Results
}

<#
.SYNOPSIS
    Parse out data from the "job complete" log records
.DESCRIPTION
    Parse out the user, job name, job GUID, owner, and filecount of BITS events with ID 4
    Returns a PSCustomObject containing all the data, with attributes matching the event records
.PARAMETER EventLog
    An individual record from an event log. The only acceptable Event ID for this function is 4
    Anything else will return no data
.EXAMPLE
    Parse-CompleteJob -EventLog $record
.NOTES
    The transfer job is complete.
    User: computer\Username
    Transfer job: Push Notification Platform Job: 1
    Job ID: {b0bd0c0e-7724-49e2-a627-7b9faaa32316}
    Owner: computer\Username
    File count: 1
#>
Function Parse-CompleteJob {
    Param(
        [EventLogRecord]$EventLog
    )
    [PSCustomObject]$Results
}

<#
.SYNOPSIS
    Parse out data from the "cancelled jobs" log records
.DESCRIPTION
    Parse out the user, job name, job GUID, owner, and filecount of BITS events with ID 5
    Returns a PSCustomObject containing all the data, with attributes matching the event records
.PARAMETER EventLog
    An individual record from an event log. The only acceptable Event ID for this function is 5
    Anything else will return no data
.EXAMPLE
    Parse-CancelledJob -EventLog $record
.NOTES
    Job cancelled.
    User: NT AUTHORITY\NETWORK SERVICE
    job: MicrosoftMapsBingGeoStore
    jobID: {8636eee8-dc04-472e-aa33-60838f7a4232}
    owner: NT AUTHORITY\NETWORK SERVICE
    filecount: 0
#>
Function Parse-CancelledJob {
    Param(
        [EventLogRecord]$EventLog
    )
    [PSCustomObject]$Results
}

<#
.SYNOPSIS
    Parse out the URL and status code of a BITS job
.DESCRIPTION
    Parse out the URL and status code of BITS events with IDs: 59, 60, and 61
    Returns a PSCustomObject containing the URL and current status code if applicable (none returned for ID 59)
.PARAMETER EventLog
    An individual record from an event log. Acceptable Event IDs for this function are 59, 60, and 61
    Anything else will return no data
.EXAMPLE
    Parse-JobStatus -EventLog $record
.NOTES
Event ID 59:
    BITS started the Push Notification Platform Job: 1 transfer job that is associated with the http://google.com/ URL.
Event ID 60:
    BITS stopped transferring the Push Notification Platform Job: 1 transfer job that is associated with the http://google.com/ URL. The status code is 0x0.
Event ID 61: (appears to be exclusively for jobs that ended early)
    BITS stopped transferring the Push Notification Platform Job: 1 transfer job that is associated with the http://google.com/ URL. The status code is 0x80072EE7.
#>
Function Parse-JobStatus {
    Param(
        [EventLogRecord]$EventLog
    )
    [PSCustomObject]$Results
}