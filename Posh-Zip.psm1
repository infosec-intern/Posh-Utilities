Function Invoke-Zip {
<#
.SYNOPSIS
    Compress a folder or collection of files into a zip archive
.PARAMETER Path
    Folder to compress into a zip archive
.PARAMETER Name
    Name of resulting zip archive
.EXAMPLE
    Invoke-Zip -Path ~/Downloads -Name downloads.zip
.LINK
    http://blogs.technet.com/b/heyscriptingguy/archive/2015/03/09/use-powershell-to-create-zip-archive-of-folder.aspx
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("Source", "SourceDirectoryName")]
        [String]$Path,
        [Parameter(Mandatory=$false,Position=1)]
        [Alias("Destination", "DestinationArchiveFileName")]
        [String]$Name,
        [Parameter(Mandatory=$false)]
        [Switch]$IncludeBaseDirectory
    )
    If (Test-Path $Path -PathType Container) {
        Add-Type -AssemblyName "System.IO.Compression.Filesystem"
        [IO.Compression.Zipfile]::CreateFromDirectory($Path, $Name)
    }
    Else {
        Throw "$Path is not an existing directory"
    }
}

Function Invoke-Unzip {
<#
.SYNOPSIS
    Extract a zip archive into a folder or collection of files
.PARAMETER Path
    Archive to extract
.PARAMETER Destination
    Folder to extract data to
.EXAMPLE
    Invoke-Unzip -Path .\downloads.zip -Destination ~/Downloads
.LINK
    http://blogs.technet.com/b/heyscriptingguy/archive/2015/03/09/use-powershell-to-create-zip-archive-of-folder.aspx
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$Path,
        [Parameter(Mandatory=$true,Position=1)]
        [String]$Destination
    )
    If (Test-Path $Path -PathType Leaf) {
        Add-Type -AssemblyName "System.IO.Compression.Filesystem"
    }
    Else {
        Throw "$Path is not a valid file"
    }
}

Export-ModuleMember Invoke-Zip
Export-ModuleMember Invoke-Unzip