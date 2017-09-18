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

Function Invoke-XOREncode {
    Param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [String]$Message,
        [string]$Secret
    )
    Write-Verbose "[*] Attempting XOR..."

    $secret_bytes = [System.Text.Encoding]::Unicode.GetBytes($Secret)
    $char_bytes = [System.Text.Encoding]::Unicode.GetBytes($Message)
    $msg_length = $char_bytes.Length
    $bytes = New-Object Byte[] $msg_length

    Write-Debug "[**] secret_array = $([System.Text.Encoding]::Unicode.GetChars($secret_bytes))"
    Write-Debug "[**] char_array = $([System.Text.Encoding]::Unicode.GetChars($char_bytes))"
    For ($i=0; $i -lt $msg_length; $i++) {
        $bytes[$i] = ($char_bytes[$i]) -bxor ($secret_bytes[($i%$secret_bytes.Length)])
    }
    $xor = [System.Text.Encoding]::Unicode.GetChars($bytes)
    Write-Output "[XOR] Encoded `"$Message`" to `"$xor`""

    For ($i=0; $i -lt $msg_length; $i++) {
        $bytes[$i] = ($secret_bytes[($i%$secret_bytes.Length)]) -bxor ($xor[$i])
    }
    $result = [System.Text.Encoding]::Unicode.GetChars($bytes)
    Write-Output "[XOR] Decoding `"$xor`" to `"$result`""
}