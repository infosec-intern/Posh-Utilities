[CmdletBinding()]
Param()

Function Invoke-Base64Encode {
    Param(
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

Function Invoke-Base64Decode {
    Param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [String]$Encoded
    )
    Write-Verbose "[*] Attempting Base64Decode..."
    $Decoded = [System.Text.Encoding]::Unicode.GetString(
        [System.Convert]::FromBase64String($Encoded)
    )
    Write-Verbose "[Base64] Decoded `"$Encoded`" to `"$Decoded`""
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