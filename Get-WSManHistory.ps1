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
            "Id"=6,10,11,13,15,16,33,142,162;
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
            $Record = ([xml]$Event.ToXML()).Event.EventData.Data
            Switch ($Event.Id) {
                6 {
                    # Creating WSMan Session. The connection string is:
                    # https://century.underthewire.tech:6010/wsman?PSVersion=5.1.15063.632
                    Write-Verbose -Message "Parsing SessionCreation -EventLog $($Event.Id)"
                    $SessionId = $Event.ActivityId
                    $Sessions[$SessionId] = New-Object -TypeName PSObject -Property @{
                        "Connection" = $Record.'#text';
                        "Id" = $SessionId;
                    }
                }
                10 {
                    # Setting WSMan Session Option (34) - WSMAN_OPTION_USE_INTEARACTIVE_TOKEN with value (0) completed successfully.
                    # Setting WSMan Session Option (1) - WSMAN_OPTION_DEFAULT_OPERATION_TIMEOUTMS with value (180000) completed successfully.
                }
                11 {
                    # Creating WSMan shell with the ResourceUri: http://schemas.microsoft.com/powershell/UTW and ShellId: EFE06CA1-17D2-40D6-A138-52CE7645116B
                    # command: Enter-PSSession -ComputerName century.underthewire.tech -UseSSL -port 6010 -configurationname UTW -Credential (Get-Credential)
                }
                13 {
                    # Running WSMan command with CommandId: 2D9967F0-3EE4-47AC-90A7-2B91CEB82BC1
                }
                15 {
                    # Closing WSMan command
                }
                16 {
                    # Closing WSMan shell
                }
                33 {
                    # Closing WSMan Session completed successfuly
                }
                142 {
                    # WSMan operation CreateShell failed, error code 5
                }
                162 {
                    # Authenticating the user failed. The credentials didn't work.
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
