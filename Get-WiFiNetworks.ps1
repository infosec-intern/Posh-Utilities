<#
.SYNOPSIS
    Extract WiFi networks this computer has connected to out of the event logs
.DESCRIPTION
    Extract WiFi networks this computer has connected to out of the event logs and the type of authentication method used. Future work may include login and logout times or number of times connected
.PARAMETER ComputerName
    Remote computer to search event logs on. Default is the local computer
.PARAMETER Credential
    PSCredential object to authenticate to a remote computer with
.PARAMETER Path
    Path to an event log (should end in .evtx) to read
.PARAMETER List
    List the WiFi network SSIDs
.EXAMPLE
    Get-WiFiNetworks

    Authentication      Ssid
    --------------      ----
    WPA2-Personal       Pretty Fly for a Wifi
    Open                att-wifi
#>
Function Get-WiFiNetworks {
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
        $Networks = @()
        $Filter = @{
            "ProviderName"="Microsoft-Windows-WLAN-AutoConfig";
            "LogName"="Microsoft-Windows-WLAN-AutoConfig/Operational";
            "Id"=8001;
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
            $Ssid = $Record.'#text'[4]
            If ($Ssid -notin $Networks) {
                $Networks += New-Object -TypeName PSObject -Property @{
                    "Ssid" = $Ssid;
                    "Authentication" = $Record.'#text'[7];
                }
            }
        }
    }
    END {
        $Networks | Sort-Object -Property Ssid -Unique
    }
}