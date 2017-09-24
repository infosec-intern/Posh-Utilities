[CmdletBinding()]
Param()
<#
.SYNOPSIS
    Some sample ETW explorations
.DESCRIPTION
    This module contains various functions and commands related to ETW (Event Tracing for Windows).
    I really have no idea what's gonna be in it, so it probably won't be all that useful on its own.
    Any future good ideas will get their own scripts/modules.
.LINK
    https://github.com/infosec-intern/Posh-Utilities/
    https://support.microsoft.com/en-us/help/2593157/event-tracing-for-windows-etw-simplified
    https://msdn.microsoft.com/en-us/library/windows/desktop/bb968803(v=vs.85).aspx
    https://www.fireeye.com/blog/threat-research/2017/09/pywintrace-python-wrapper-for-etw.html
    https://blogs.msdn.microsoft.com/ntdebugging/2009/09/08/part-2-exploring-and-decoding-etw-providers-using-event-log-channels/
    https://technet.microsoft.com/en-us/library/dn168858.aspx
    https://www.youtube.com/watch?v=VABMu05mYww
#>

$TargetProvider = "Microsoft-Windows-PowerShell"
$EventID = 7937
$Field = "ContextInfo"

# 1. Create a trace session
# 2. Register one or more providers with the trace session
# 3. For each provider, set the appropriate "any" and "all" flags
# 4. Register a callback
# 5. Start the trace session
# 6. Process events (indefinitely)
    # 6.1. receive event
    # 6.2. get the schema for the event
    # 6.3. parse out the data field of the event you are interested in based on the schema from (2)
# 7. Stop the trace session

