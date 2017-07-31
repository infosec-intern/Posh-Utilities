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
    List the completed BITS sessions
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

# Event ID 3 shows start times and session ID
#   The BITS service created a new job.
#   Transfer job: Push Notification Platform Job: 1
#   Job ID: {b652f1e5-5a4f-4a3c-9673-21b527e3b142}
#   Owner: computer\Username
#   Process Path: C:\Windows\System32\svchost.exe
#   Process ID: 3388
# Event ID 4 shows stop times and session ID
#   The transfer job is complete.
#   User: computer\Username
#   Transfer job: Push Notification Platform Job: 1
#   Job ID: {b0bd0c0e-7724-49e2-a627-7b9faaa32316}
#   Owner: computer\Username
#   File count: 1
# Event ID 5 shows cancelled jobs
#   Job cancelled. User: NT AUTHORITY\NETWORK SERVICE, job: MicrosoftMapsBingGeoStore, jobID: {8636eee8-dc04-472e-aa33-60838f7a4232}, owner: NT AUTHORITY\NETWORK SERVICE, filecount: 0
# Event IDs 59, 60, & 61 show URL for session. 61 appears to be exclusively for jobs that ended early
#   BITS started the Push Notification Platform Job: 1 transfer job that is associated with the http://google.com/ URL.
#   BITS stopped transferring the Push Notification Platform Job: 1 transfer job that is associated with the http://google.com/ URL. The status code is 0x0.
#   BITS stopped transferring the Push Notification Platform Job: 1 transfer job that is associated with the http://google.com/ URL. The status code is 0x80072EE7.