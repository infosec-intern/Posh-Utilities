<#
.SYNOPSIS
    Analyze event logs for information about any PSSession remote management sessions (also known as WSMan)
.DESCRIPTION
    Analyze event logs for information about any PSSession remote management sessions (also known as WSMan).
    This includes when sessions are started and stopped, extracting any hex-encoded commands run during the sessions,
    and reporting any errors that occurred during the sessions
.PARAMETER ComputerName
    Remote computer to search event logs on. Default is the local computer
.PARAMETER Credential
    PSCredential object to authenticate to a remote computer with
.PARAMETER Path
    Path to an event log (should end in .evtx) to read
.PARAMETER List
    List the WSMan sessions and their start/stop times
.EXAMPLE
    .\Get-WSManHistory.ps1
.LINK
    https://github.com/infosec-intern/Posh-Utilities/
    Advanced Functions: https://technet.microsoft.com/en-us/library/hh413265.aspx
.NOTES
    Event ID
#>
Function Get-WSManHistory {
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
        $Filter = @{
            "ProviderName"="Microsoft-Windows-WinRM";
            "LogName"="Microsoft-Windows-WinRM/Operational";
            "Id"=6,10,11,13,33,162;
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
        $Sessions = @{}
        ForEach ($Event in $Events) {
            $Record = ([xml]$Event.ToXML()).Event.EventData.ChildNodes
            $SessionId = $Event.ActivityId
            Switch ($Event.Id) {
                6 {
                    # Creating WSMan Session. The connection string is:
                    # https://century.underthewire.tech:6010/wsman?PSVersion=5.1.15063.632
                    Write-Verbose -Message "Session Creation: $($Event.Id)"
                    $Sessions[$SessionId] = New-Object -TypeName PSObject -Property @{
                        "Connection" = $Record.'#text';
                        "SessionId" = $SessionId;
                        "SessionCreated" = $Event.TimeCreated;
                    }
                }
                10 {
                    # Setting WSMan Session Option (34) - WSMAN_OPTION_USE_INTEARACTIVE_TOKEN with value (0) completed successfully.
                    # Setting WSMan Session Option (1) - WSMAN_OPTION_DEFAULT_OPERATION_TIMEOUTMS with value (180000) completed successfully.
                    Write-Verbose -Message "Session Option tokens: $($Event.Id)"
                    If (-not $Sessions[$SessionId].SessionOptions) {
                        $Sessions[$SessionId] | Add-Member -MemberType NoteProperty -Name "SessionOptions" -Value @();
                    }
                    $Token = New-Object -TypeName PSObject -Property @{
                        "Code" = $Record[0].'#text';
                        "Name" = $Record[1].'#text';
                        "Value" = $Record[2].'#text';
                    }
                    $Sessions[$SessionId].SessionOptions += $Token
                }
                11 {
                    # Creating WSMan shell with the ResourceUri: http://schemas.microsoft.com/powershell/UTW and ShellId: EFE06CA1-17D2-40D6-A138-52CE7645116B
                    # command: Enter-PSSession -ComputerName century.underthewire.tech -UseSSL -port 6010 -configurationname UTW -Credential (Get-Credential)
                    # ShellTypes defined by resource URI: https://msdn.microsoft.com/en-us/library/aa384461(v=vs.85).aspx
                    Write-Verbose -Message "Resource Shell Creation: $($Event.Id)"
                    $Uri = $Record[0].'#text'
                    $Sessions[$SessionId] | Add-Member -MemberType NoteProperty -Name "ResourceUri" -Value $Uri -Force -ErrorAction Ignore
                }
                13 {
                    # Running WSMan command with CommandId: 2D9967F0-3EE4-47AC-90A7-2B91CEB82BC1
                    Write-Verbose -Message "Command Execution: $($Event.Id)"
                    $Sessions[$SessionId] | Add-Member -MemberType NoteProperty -Name "CommandId" -Value $Record.'#text' -Force -ErrorAction Ignore
                }
                33 {
                    # Closing WSMan Session completed successfully
                    Write-Verbose -Message "Session Close Complete: $($Event.Id)"
                    $Sessions[$SessionId] | Add-Member -MemberType NoteProperty -Name "SessionClosed" -Value $Event.TimeCreated -Force -ErrorAction Ignore
                }
                142 {
                    If ($Record[0].'#text' -eq "CreateShell") {
                        # WSMan operation CreateShell failed, error code 5
                        Write-Verbose -Message "Session Creation Failed: $($Event.Id)"
                        $Sessions[$SessionId] | Add-Member -MemberType NoteProperty -Name "SessionClosed" -Value $Event.TimeCreated -Force -ErrorAction Ignore
                        $Sessions[$SessionId] | Add-Member -MemberType NoteProperty -Name "FailureReason" -Value $Record[1].'#text' -Force -ErrorAction Ignore
                    }
                }
                162 {
                    # Authenticating the user failed. The credentials didn't work.
                    Write-Verbose -Message "User Authentication Failed: $($Event.Id)"
                    $Sessions[$SessionId] | Add-Member -MemberType NoteProperty -Name "FailureReason" -Value "User Authentication failed" -Force -ErrorAction Ignore
                }
                Default {
                    Write-Warning -Message "I can't parse event ID $($Event.Id)"
                }
            }
        }
    }
    END {
        Write-Output -InputObject $Sessions.Values
    }
}
