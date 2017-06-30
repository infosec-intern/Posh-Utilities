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
    https://msdn.microsoft.com/en-us/library/system.io.compression.compressionlevel(v=vs.110).aspx
    https://msdn.microsoft.com/en-us/library/hh485707(v=vs.110).aspx
    https://msdn.microsoft.com/en-us/library/hh485724(v=vs.110).aspx
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
        [Switch]$IncludeBaseDirectory,
        [Parameter(Mandatory=$false)]
        [ValidateSet("Fastest","NoCompression","Optimal")]
        $CompressionLevel
    )
    Add-Type -AssemblyName "System.IO.Compression.Filesystem"
    switch ($CompressionLevel) {
        "Optimal" {
            $CompressionLevel = [System.IO.Compression.CompressionLevel]::Optimal
        }
        "Fastest" {
            $CompressionLevel = [System.IO.Compression.CompressionLevel]::Fastest
        }
        "NoCompression" {
            $CompressionLevel = [System.IO.Compression.CompressionLevel]::NoCompression
        }
        Default {
            $CompressionLevel = [System.IO.Compression.CompressionLevel]::Optimal
        }
    }
    If (Test-Path $Path -PathType Container) {
        [System.IO.Compression.ZipFile]::CreateFromDirectory($Path, $Name, $CompressionLevel, $IncludeBaseDirectory)
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
    Folder to extract data to. Default is the current folder
.EXAMPLE
    Invoke-Unzip -Path .\downloads.zip -Destination ~/Downloads
.LINK
    http://blogs.technet.com/b/heyscriptingguy/archive/2015/03/09/use-powershell-to-create-zip-archive-of-folder.aspx
    https://msdn.microsoft.com/en-us/library/hh485723(v=vs.110).aspx
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("Source", "SourceArchiveFileName")]
        [String]$Path,
        [Parameter(Mandatory=$true,Position=1)]
        [Alias("DestinationDirectoryName")]
        [String]$Destination = "$(Convert-Path -Path .)"
    )
    Write-Verbose -Message "Extracting archive into '$Destination'"
    If (Test-Path $Path -PathType Leaf) {
        Add-Type -AssemblyName "System.IO.Compression.Filesystem"
        [System.IO.Compression.ZipFile]::ExtractToDirectory($Path, $Destination)
        If (Test-Path $Destination) {
            Write-Verbose -Message "Successfully extracted to '$Destination'"
        }
    }
    Else {
        Throw "$Path is not a valid file"
    }
}

Export-ModuleMember Invoke-Zip
Export-ModuleMember Invoke-Unzip