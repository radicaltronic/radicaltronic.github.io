
function Get-Base64FromUrl {
    [CmdletBinding(SupportsShouldProcess)]
    Param
    (
        [Parameter(Mandatory = $true)]
        [String]$Url
    )
    try {
            OutString "Get-Base64FromUrl: $Url"
            $webclient = New-Object Net.WebClient
            $DownloadedData = $webclient.DownloadString($Url)
            $Bytes = [System.Text.Encoding]::Unicode.GetBytes($DownloadedData) 
            $Base64 = [Convert]::ToBase64String($Bytes)
            $Base64CommandLen=$Base64Command.Length
            $DownloadedDataLen=$DownloadedData.Length
            OutString "`tsuccess! Downloaded $DownloadedDataLen bytes"
            OutString "`tsuccess! Converted to $Base64CommandLen bytes in Base64"
            return $Base64 
    }
    catch
    {
        $Msg="Get-Base64FromUrl Ran into an issue: $($PSItem.ToString())"
        if($env:COMPUTERNAME.substring(6) -like 'CK' -Or $env:COMPUTERNAME.substring(6) -like 'PS') {
            write-host '[install]   ' -NoNewLine -f Red
            write-host $Msg -f DarkYellow
            Write-Verbose $Msg
            #write-host '[test-exceptions] ' -NoNewLine -f Red
        #write-host $Msg -f DarkYellow
        }

        write-verbose $Msg 
        if($PSCmdlet -ne $null){
            $PSCmdlet.ThrowTerminatingError($PSItem)
        }
        
    }   
}

