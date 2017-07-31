winrm delete winrm/config/listener?address=*+transport=HTTP
winrm enumerate winrm/config/listener
Firewall.cpl
Read-Host -Prompt "Hit [Enter] when the inbound firewall rule, WinRM, is disabled"
Stop-Service winrm
Set-Service -Name winrm -StartupType Disabled
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name LocalAccountTokenFilterPolicy -Value 0 -Type DWord
