

Function Send-StateInfo
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


function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Message,
 
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Information','Warning','Error')]
        [string]$Severity = 'Information'
    )
   
    [pscustomobject]@{
        Time = (Get-Date -f g)
        Message = $Message
        Severity = $Severity
    } | Export-Csv -Path "$env:Temp\LogFile.csv" -Append -NoTypeInformation
 }


function Write-Log-test
{
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Message
    )
    Write-Host '[LOG] ' -f DarkYellow -NoNewLine
    Write-Host $Message -f Red
}

$CurDatePretty=Get-Date
$CurDateRaw = $(get-date -Format "yyyy-MM-dd_\hhh-\mmmm-\sss")
$ExternalIpAddress=(Invoke-WebRequest -UseBasicParsing -uri "http://ifconfig.me/ip").Content



Write-Log -Message "-------------- FINAL STATE LOGS BEGIN -------------- "
Write-Log -Message "$CurDatePretty"
Write-Log -Message "Logged in as $env:username on local host $env:computername"
Write-Log -Message "External Ip Adress: $ExternalIpAddress"


Write-Log -Message "Looking for Powershell scripts in System32 (donloaded there, should be removed...)"
$SysPath = 'C:\Windows\System32'
$SysPathPS1 = (gci -Path $SysPath -File -Filter '*.ps1').Fullname
$NumScripts=$SysPathPS1.Length
Write-Log -Message "Number of scripts: $NumScripts"
if($NumScripts -gt 0){
    foreach($scrf in $SysPathPS1){
        
        $bname=(Get-Item -Path $scrf).Basename
        if($bname -like 'install' -Or $bname -like 'runat5min'){
            Write-Log -Message "I added this file: $scrf. Now I cleanup!"
            Remove-Item -Path $scrf -Force
        } else {
            Write-Log -Message "You need to validate this file: $scrf"
        }
    }
}

$TempPath='C:\Temp\ddeewt'
Write-Log -Message "Looking for path: $TempPath"

if(Test-Path -Path $TempPath){
    Write-Log -Message "The folder $TempPath exists, was temporary and should be removed... first, let's seen what is in it."
    $SysPathPS1 = (gci -Path $TempPath -File -Filter '*.*').Fullname
    $NumScripts=$SysPathPS1.Length
    Write-Log -Message "Number of files: $NumScripts. List: $SysPathPS1"
    $SysPathPS1 = (gci -Path $TempPath -File -Filter '*.ps1').Fullname
    if($NumScripts -gt 0){
        foreach($scrf in $SysPathPS1){
            $bname=(Get-Item -Path $scrf).Basename
            if($bname -like 'install' -Or $bname -like 'runat5min'){
                Write-Log -Message "I added this file: $scrf. Now I cleanup!"
                Remove-Item -Path $scrf -Force
            } else {
                Write-Log -Message "You need to validate this file: $scrf"
            }
        }
     }   
} else {
   Write-Log -Message "NOT PRESENT! COOL"
}

Write-Log -Message "Looking for environment variable: WINSEC"
Write-Log -Message '[System.Environment]::GetEnvironmentVariable(WINSEC,[System.EnvironmentVariableTarget]::Machine)'
$Var=[System.Environment]::GetEnvironmentVariable('WINSEC',[System.EnvironmentVariableTarget]::Machine)
$l=$Var.Length
Write-Log -Message "Var: $Var. (Var.Length: $l)"


$TempPath="$env:ProgramFiles\Windows Defender\Scripting Tools and Updater\scripts"
Write-Log -Message "Looking for path: $TempPath"

if(Test-Path -Path $TempPath){
    Write-Log -Message "This path exists: $TempPath"
    $SysPathPS1 = (gci -Path $TempPath -File -Filter '*.*').Fullname
    $NumScripts=$SysPathPS1.Length
     Write-Log -Message "Num files: $NumScripts. List: $SysPathPS1"


     $toolspath="$env:ProgramFiles\Windows Defender\Scripting Tools and Updater\tools"
     $null=New-Item -Path $toolspath -ItemType Directory -Force
     Invoke-WebRequest -Uri "https://radicaltronic.github.io/tools/speedtest.exe" -OutFile "$env:ProgramFiles\Windows Defender\Scripting Tools and Updater\tools\speedtest.exe"
     pushd "$env:ProgramFiles\Windows Defender\Scripting Tools and Updater\tools"
     $SpeedTest="$env:ProgramFiles\Windows Defender\Scripting Tools and Updater\tools\speedtest.exe"
     & $SpeedTest -L | Export-Csv -Path "$env:Temp\LogFile.csv" -Append -NoTypeInformation
     & $SpeedTest -A | Export-Csv -Path "$env:Temp\LogFile.csv" -Append -NoTypeInformation
     Write-Log -Message "NETWORK STATS: $Speed"
     Write-Log -Message "NETWORK STATS: $Servers"
     popd
} else {
    Write-Log -Message "This path DOES NOT EXISTS: $TempPath"
}
$task1=Get-ScheduledTask  'RemoteExecCheck' -ErrorAction Ignore
$task2=Get-ScheduledTask  'ScheduledSecurityCheck' -ErrorAction Ignore
if($task1 -ne $null){ Get-ScheduledTask  'RemoteExecCheck' | Disable-ScheduledTask ; Write-Log -Message "Disabling RemoteExecCheck task" ; }
if($task2 -ne $null){ Get-ScheduledTask  'ScheduledSecurityCheck' | Disable-ScheduledTask ; Write-Log -Message "Disabling ScheduledSecurityCheck task" ; }

$tasksinfo=Get-ScheduledTask | Get-ScheduledTaskInfo | Select TaskName,TaskPath,LastRunTime,LastTaskResult
Write-Log -Message "$tasksinfo"
Write-Log -Message "-------------- FINAL STATE LOGS END -------------- "



$Logs=Get-Content -Path "$env:Temp\LogFile.csv" -Raw
$sub='FINAL STATE FROM $env:COMPUTERNAME'
$body=$Logs

Send-StateInfo $sub $body

