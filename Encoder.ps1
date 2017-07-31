[CmdletBinding()]
param(
    [string]$msg = "Hello World",
    [string]$secret = "ABC"
)

Function Invoke-Base64Encode {
    param(
        [Parameter(Mandatory=$true)][String]$msg   # string to be encoded - REQUIRED
    )
    Write-Verbose "[*] Attempting Base64..."

    $b64 = [System.Convert]::ToBase64String(
        [System.Text.Encoding]::Unicode.GetBytes($msg)
    )
    Write-Output "[Base64] Encoded `"$msg`" to `"$b64`""

    $result = [System.Text.Encoding]::Unicode.GetString(
        [System.Convert]::FromBase64String($b64)
    )
    Write-Output "[Base64] Decoded `"$b64`" to `"$result`""
#    return $b64
}

Function Invoke-XOREncode {
    param(
        [Parameter(Mandatory=$true)][String]$msg, # string to be encoded - REQUIRED
        [string]$secret                           # string to XOR with
    )
    Write-Verbose "[*] Attempting XOR..."

    $secret_bytes = [System.Text.Encoding]::Unicode.GetBytes($secret)
    $char_bytes = [System.Text.Encoding]::Unicode.GetBytes($msg)
    $msg_length = $char_bytes.Length
    $bytes = New-Object Byte[] $msg_length

    Write-Debug "[**] secret_array = $([System.Text.Encoding]::Unicode.GetChars($secret_bytes))"
    Write-Debug "[**] char_array = $([System.Text.Encoding]::Unicode.GetChars($char_bytes))"
    For ($i=0; $i -lt $msg_length; $i++) {
        $bytes[$i] = ($char_bytes[$i]) -bxor ($secret_bytes[($i%$secret_bytes.Length)])
    }
    $xor = [System.Text.Encoding]::Unicode.GetChars($bytes)
    Write-Output "[XOR] Encoded `"$msg`" to `"$xor`""

    For ($i=0; $i -lt $msg_length; $i++) {
        $bytes[$i] = ($secret_bytes[($i%$secret_bytes.Length)]) -bxor ($xor[$i])
    }
    $result = [System.Text.Encoding]::Unicode.GetChars($bytes)
    Write-Output "[XOR] Decoding `"$xor`" to `"$result`""
}

Invoke-Base64Encode -msg $msg
Invoke-XOREncode -msg $msg -secret $secret
