# Taken From:
# http://blogs.technet.com/b/heyscriptingguy/archive/2015/03/09/use-powershell-to-create-zip-archive-of-folder.aspx
Function Invoke-Zip {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)]
			[String]$Path,
        	[Parameter(Mandatory=$false,Position=1)]
            		[String]$Name,
        	[Parameter(Mandatory=$false)]
            		[Switch]$Force
	)
	Begin
	{
        	Write-Verbose "Invoke-Zip: BEGIN"
        	Write-Verbose "`$Path = $Path"
        	if (-not (Test-Path $Path -PathType Container))
        	{
            		Throw "$Path is not an existing directory"
        	}
        	Write-Verbose "Adding IO.Compression assembly"
        	Add-Type -AssemblyName "System.IO.Compression.Filesystem"
	}
	Process
	{
        	Write-Verbose "Invoke-Zip: PROCESS"
        	[IO.Compression.Zipfile]::CreateFromDirectory($Path, $Name)
	}
	End
	{
        	Write-Verbose "Invoke-Zip: END"
	}
}

# Taken From:
# http://blogs.technet.com/b/heyscriptingguy/archive/2015/03/09/use-powershell-to-create-zip-archive-of-folder.aspx
Function Invoke-Unzip {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)]
			[String]$Path,
        	[Parameter(Mandatory=$true,Position=1)]
            		[String]$Destination
	)
	Begin
	{
        	Write-Verbose "Invoke-Unzip: BEGIN"
        	Add-Type -AssemblyName "System.IO.Compression.Filesystem"
	}
	Process
	{
        	Write-Verbose "Invoke-Unzip: PROCESS"
	}
	End
	{
        	Write-Verbose "Invoke-Unzip: END"
	}
}

Export-ModuleMember Invoke-Zip
Export-ModuleMember Invoke-Unzip