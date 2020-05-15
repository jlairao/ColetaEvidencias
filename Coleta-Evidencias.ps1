<#
.SYNOPSIS
   Name: Coleta-Evidencias.ps1
   The purpose of this script is to collect evidences of certain configurations required for
   complete the zctivation process of Windows Servers from IBM customers.

.DESCRIPTION
   This script collects information about:
   . Security Policies (SECPOL) - Passwords and auditing
   . Log Retention
   . System Information

.PARAMETER Computer name
   This is the only parameter required for the script to run.
   The list of servers where the script should be executed, must be contained in a text file
   (SERVERS.TXT) in the following format:

  HOSTNAME
  HOSTNAME
  HOSTNAME
  ...

.NOTES
Minimum requirements:
   Operating System: Windows Server 2008 R2 and higher.
   Powershell: Version 4 and higher
   Release Date: 3/17/2020
   Author: Jose Luiz Airao - jlairao@br.ibm.com

#>

Function Parse-SecPol($CfgFile){ 
    secedit /export /cfg "$CfgFile" | out-null
    $obj = New-Object psobject
    $index = 0
    $contents = Get-Content $CfgFile -raw
    [regex]::Matches($contents,"(?<=\[)(.*)(?=\])") | %{
        $title = $_
        [regex]::Matches($contents,"(?<=\]).*?((?=\[)|(\Z))", [System.Text.RegularExpressions.RegexOptions]::Singleline)[$index] | %{
            $section = new-object psobject
            $_.value -split "\r\n" | ?{$_.length -gt 0} | %{
                $value = [regex]::Match($_,"(?<=\=).*").value
                $name = [regex]::Match($_,".*(?=\=)").value
                $section | add-member -MemberType NoteProperty -Name $name.tostring().trim() -Value $value.tostring().trim() -ErrorAction SilentlyContinue | out-null
            }
            $obj | Add-Member -MemberType NoteProperty -Name $title -Value $section
        }
        $index += 1
    }
    return $obj
}

$FilePath = "c:\ibm_support\ps\servers.txt"

if (Test-Path $FilePath -PathType leaf) 

{

Clear-Host
Set-Location -path "c:\ibm_support\ps"
Write-host  @"
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
::::::::::::::::::::::::::  IBM Project Services ::::::::::::::::::::::::
:::::::::::::::::: Windows Server Evidence Collection Script ::::::::::::
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

"@ 

foreach($Server in [System.IO.File]::ReadLines("C:\ibm_support\ps\servers.txt")) {
        Write-host "Starting collection info from server " $Server -f yellow
        write-host 
        $Connection = Test-Connection $Server -Count 1 -Quiet
      
        if ($Connection -eq "True") {

            $GetServerSecPol = Parse-SecPol("C:\ibm_support\ps\Secpol.cfg")
            $session = New-PSSession -ComputerName $Server
            $sID = Get-PSSession
            Invoke-Command -session $session -ScriptBlock {$GetServerSecPol}
            remove-item "C:\ibm_support\ps\Secpol.cfg" -Force

            # Export the result to evidence file
            $ResultFile =  ".\$Server-SecPol.txt"
        
            if(($GetServerSecPol.'System Access'.PasswordComplexity -eq 0)) {$PolComp = "Disabled"} else {$PolComp = "Enabled"}
            if(($GetServerSecPol.'System Access'.ClearTextPassword -eq 0)) {$Encryp = "Disabled"} else {$Encryp = "Enabled"}

            $Line = "Password Policy"
            Add-Content $ResultFile $Line
            $Line = "---------------"
            Add-Content $ResultFile $Line
            $Line = "Maximum Password Age                      : "+$GetServerSecPol.'System Access'.MaximumPasswordAge+" Days" 
            Add-Content $ResultFile $Line
            $Line = "EnforcePassword History                   : "+$GetServerSecPol.'System Access'.PasswordHistorySize+" Passwords Remembered"
            Add-Content $ResultFile $Line
            $Line = "Minimum Password Age                      : "+$GetServerSecPol.'System Access'.MinimumPasswordAge+" Days"
            Add-Content $ResultFile $Line
            $Line = "Minimum Password Lengh                    : "+$GetServerSecPol.'System Access'.MinimumPasswordLength+" Characters"
            Add-Content $ResultFile $Line
            $Line = "Password Must Meet Complexity Requeriments: "+$PolComp
            Add-Content $ResultFile $Line
            $Line = "Store Passord Using Reversible Encryption : "+$Encryp
            Add-Content $ResultFile $Line
            $Line = " "
            Add-Content $ResultFile $Line
            Add-Content $ResultFile $Line
            $Line = "Account Lockout Policy"
            Add-Content $ResultFile $Line
            $Line = "----------------------"
            Add-Content $ResultFile $Line
            $Line = "Account Lockout duration                  : "+$GetServerSecPol.'System Access'.LockoutDuration
            Add-Content $ResultFile $Line
            $Line = "Account Lockout Threshold                 : "+$GetServerSecPol.'System Access'.LockoutBadCount+" Invalid Logon Attempts"
            Add-Content $ResultFile $Line
            $Line = "Reset Account Lockout Counter After       : "+$GetServerSecPol.'System Access'.ResetLockoutCount+" Minutes"
            Add-Content $ResultFile $Line

            # Export log retention settings to evidence file

            $Line = " "
            Add-Content $ResultFile $Line
            Add-Content $ResultFile $Line
            $Line = "Retention Logs Configuration"
            Add-Content $ResultFile $Line
            $Line = "-----------------------------------"
            Add-Content $ResultFile $Line
            $Logs  = Invoke-Command -session $session -ScriptBlock {Get-EventLog -List | Where-Object {($_.Log -eq 'System') -or ($_.Log -eq 'Application') -or ($_.Log -eq 'Security')} | Format-List}
            $Logs | Out-File .\$server-Logs.txt
            $LogRetain = Get-Content .\$server-Logs.txt
            Remove-Item .\$server-Logs.txt -Force
            Add-Content $ResultFile $LogRetain
            $Line = " "
            Add-Content $ResultFile $Line
            Add-Content $ResultFile $Line
            $Line = "Advanced Audit Policy Configuration"
            Add-Content $ResultFile $Line
            $Line = "-----------------------------------"
            Add-Content $ResultFile $Line


            # Performs the export of the Audit Policy settings to the evidence file
            $AuditPolicy = Invoke-Command -session $session -ScriptBlock {auditpol.exe /get /category:*} 
            Add-Content .\$Server-secpol.txt $AuditPolicy

            # Performs the export of installed hotfixes to the evidence file
            $Hotfixes = Invoke-Command -session $session -ScriptBlock {Get-HotFix} 
            $Hotfixes | out-file .\$server-Hotfix.txt

            # Performs the export of basic information from the Server to the evidence file
            $ComputerCPU = Invoke-Command -session $session -ScriptBlock {Get-CimInstance -ClassName Win32_Processor -Property * } 
            $ComputerCPU.numberofcores| Out-file -FilePath .\cores.txt 
            $ComputerCPU.name | out-file -FilePath .\name.txt
         

            $ResultFile = ".\$server-SystemInfo.txt"
            $SystemInfo = Invoke-Command -session $session -ScriptBlock {Get-CimInstance -ClassName Win32_OperatingSystem -Property *}
            $tab = "`t`t`t : "
            $Line = "System Information Configuration"
            Add-Content $ResultFile $Line
            $Line = "--------------------------------"
            Add-Content $ResultFile $Line
            $Line = " "
            Add-Content $ResultFile $Line
            $Line = "Operational System"+$tab+$SystemInfo.Caption
            Add-Content $ResultFile $Line
            $Line = "Install Date      "+$tab+$SystemInfo.installDate
            Add-Content $ResultFile $Line
            $Line = "Class Name        "+$tab+$SystemInfo.CreationClassName
            Add-Content $ResultFile $Line
            $Line = "Host Name         "+$tab+$SystemInfo.CSName
            Add-Content $ResultFile $Line
            $Line = "Current Time Zone "+$tab+$SystemInfo.CurrentTimeZone
            Add-Content $ResultFile $Line
            $Line = "Last Boot Time    "+$tab+$SystemInfo.LastBootUpTime
            Add-Content $ResultFile $Line
            $Line = "Local Date Time   "+$tab+$SystemInfo.LocalDateTime
            Add-Content $ResultFile $Line
            $Line = "Total Visible RAM "+$tab+$SystemInfo.TotalVisibleMemorySize
            Add-Content $ResultFile $Line
            $Line = "OS Version        "+$tab+$SystemInfo.Version
            Add-Content $ResultFile $Line
            $Line = "Build Number      "+$tab+$SystemInfo.BuildNumber
            Add-Content $ResultFile $Line
            $Line = "Build Type       "+$tab+$SystemInfo.BuildType
            Add-Content $ResultFile $Line
            $Line = "Boot Device       "+$tab+$SystemInfo.BootDevice
            Add-Content $ResultFile $Line
            $Line = "Country Code      "+$tab+$SystemInfo.CountryCode
            Add-Content $ResultFile $Line
            $Line = "Encryption Level  "+$tab+$SystemInfo.EncryptionLevel
            Add-Content $ResultFile $Line
            $Line = "MUILanguages      "+$tab+$SystemInfo.MUILanguages
            Add-Content $ResultFile $Line
            $Line = "OS Architecture   "+$tab+$SystemInfo.OSArchitecture
            Add-Content $ResultFile $Line
            $Line = "OS Language       "+$tab+$SystemInfo.OSLanguage
            Add-Content $ResultFile $Line
            $Line = "OS Serial Number  "+$tab+$SystemInfo.SerialNumber
            Add-Content $ResultFile $Line
            $Line = "SP Major Version  "+$tab+$SystemInfo.ServicePackMajorVersion
            Add-Content $ResultFile $Line
            $Line = "SP Minor Version  "+$tab+$SystemInfo.ServicePackMinorVersion
            Add-Content $ResultFile $Line
            $Line = "System Directory  "+$tab+$SystemInfo.SystemDirectory
            Add-Content $ResultFile $Line
            $Line = "System Drive      "+$tab+$SystemInfo.SystemDrive 
            Add-Content $ResultFile $Line
            $Line = "Windows Directory "+$tab+$SystemInfo.WindowsDirectory 
            Add-Content $ResultFile $Line
            $CpuCores= Get-Content -Path .\cores.txt | Measure-Object -sum          
            $Line = "CPU Total Cores   "+$tab+$CpuCores.sum
            Add-Content $ResultFile $Line          
            $Line = "CPU Cores/Sockets "+$tab+($CpuCores.Count)
            Add-Content $ResultFile $Line         
            $Line = "CPU Core          "+$tab+($CpuCores.sum/$CpuCores.Count)
            Add-Content $ResultFile $Line                  
            $CpuNames= Get-Content -Path .\name.txt -Tail 1
            $Line = "CPU Name          "+$tab+$CpuNames
            Add-Content $ResultFile $Line

            Remove-PSSession $sID.Id
            Write-host "===> The Server info collection was successful <===" -f Green
            write-host

            # Compresses the evidence files with the server name
            $ZipFile = $Server+'-Evidences-Intel.zip'
            Compress-Archive .\$Server-SystemInfo.txt, .\$Server-SecPol.txt, .\$server-HotFix.txt -DestinationPath .\$ZipFile -Force

            # Removes files that have been zipped
            remove-item .\$server-Secpol.txt, .\$server-Hotfix.txt, .\$server-SystemInfo.txt, .\cores.txt, .\name.txt -Force

        } Else {
            Write-Host "The server $Server is not responding on the network or does not exist." -f Red 
            write-host
        }
       
    }


Write-host  @"
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:::::::::::::::::::::::::::: script done ! ::::::::::::::::::::::::::::::
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
"@ 
 } else {

Clear-Host
Write-Host
Write-Host "The servers.txt file does not exist! please check it!!" -f Red 
Write-Host
}