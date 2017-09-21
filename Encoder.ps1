[CmdletBinding()]
Param()
<#
.SYNOPSIS
    Encode a string using base64
.DESCRIPTION
    Encode a Unicode string using base64 using the 'ToBase64String' function from the [System.Convert] C# namespace
.PARAMETER Message
    String to be encoded

    Aliases: From, Input, Msg
.EXAMPLE
    Invoke-Base64Encode -Message "Hello world"
    SABlAGwAbABvACAAdwBvAHIAbABkAA==
.EXAMPLE
    echo "Hello world" | Invoke-Base64Encode
    SABlAGwAbABvACAAdwBvAHIAbABkAA==
.LINK
    https://github.com/infosec-intern/Posh-Utilities/
#>
Function Invoke-Base64Encode {
    Param(
        [Alias("From", "Input", "Msg")]
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [String]$Message
    )
    Write-Verbose "[*] Attempting Base64Encode..."

    $Encoded = [System.Convert]::ToBase64String(
        [System.Text.Encoding]::Unicode.GetBytes($Message)
    )
    Write-Verbose "[Base64] Encoded `"$Message`" to `"$Encoded`""
    Write-Output $Encoded
}

<#
.SYNOPSIS
    Decode a base64 string
.DESCRIPTION
    Decode a base64 string to Unicode using the 'FromBase64String' function in the [System.Convert] C# namespace
.PARAMETER Message
    String to be decoded

    Aliases: Encoded, From, Input, Msg
.EXAMPLE
    Invoke-Base64Decode -Encoded "SABlAGwAbABvACAAdwBvAHIAbABkAA=="
    Hello World
.EXAMPLE
    echo "Hello world" | Invoke-Base64Encode
    SABlAGwAbABvACAAdwBvAHIAbABkAA==
.LINK
    https://github.com/infosec-intern/Posh-Utilities/
#>
Function Invoke-Base64Decode {
    Param(
        [Alias("Encoded", "From", "Input", "Msg")]
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [String]$Message
    )
    Write-Verbose "[*] Attempting Base64Decode..."
    $Decoded = [System.Text.Encoding]::Unicode.GetString(
        [System.Convert]::FromBase64String($Message)
    )
    Write-Verbose "[Base64] Decoded `"$Message`" to `"$Decoded`""
    Write-Output $Decoded
}

Function Invoke-XOR {
    Param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [String]$Message,
        [string]$Secret
    )
    Write-Verbose "[*] Attempting XOR..."

    $SecretBytes = [System.Text.Encoding]::Unicode.GetBytes($Secret)
    $CharBytes = [System.Text.Encoding]::Unicode.GetBytes($Message)
    $Bytes = New-Object Byte[] $CharBytes.Length

    Write-Debug "[**] secret_array = $([System.Text.Encoding]::Unicode.GetChars($SecretBytes))"
    Write-Debug "[**] char_array = $([System.Text.Encoding]::Unicode.GetChars($CharBytes))"
    For ($i=0; $i -lt $CharBytes.Length; $i++) {
        $Bytes[$i] = ($CharBytes[$i]) -bxor ($SecretBytes[($i%$SecretBytes.Length)])
    }
    $Encrypted = [System.Text.Encoding]::Unicode.GetChars($Bytes)
    Write-Verbose "[XOR] Encrypted `"$Message`" to `"$Encrypted`""
    Write-Output $Encrypted
}