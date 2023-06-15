#Create a hash table to store system information
$systeminfo = @{}

#Collect Computer Name
$systeminfo.Computername = (Get-WmiObject -Class Win32_ComputerSystem).Name

#Virtual or Physical
$systeminfo.Manufacturer = (Get-WmiObject -Class Win32_ComputerSystem).Manufacturer
$systeminfo.Model = (Get-WmiObject -Class Win32_ComputerSystem).Model

#Collect Operating System
$systeminfo.OperatingSystem = (Get-WmiObject -Class Win32_OperatingSystem).Caption

#Collect Total Physical Memory
$RAM = Get-WmiObject -Class Win32_OperatingSystem | Select-Object TotalVisibleMemorySize, FreePhysicalMemory
$TotalRAM = [int]($RAM.TotalVisibleMemorySize / 1024)
$FreeRAM = [int]($RAM.FreePhysicalMemory / 1024)
$UsedRAM = $TotalRAM - $FreeRAM
$systeminfo.TotalPhysicalMemory = "$TotalRAM"

#Collect CPU Information
$systeminfo.ProcessorInfo = (Get-WmiObject -Class Win32_Processor -ComputerName. | Select-Object Name)


#Logical Processors are with hyperthreading
$cs = Get-WmiObject -class Win32_ComputerSystem
$systeminfo.ProcessorCount = $cs.numberofprocessors



#Collect OSArchitecture
$systeminfo.Architecture = $Env:PROCESSOR_ARCHITECTURE

#Collect Disk Information
$systeminfo.Disks = (Get-WmiObject -Class Win32_LogicalDisk | Select-Object DeviceID, Size, FreeSpace, VolumeName)

#Collect all Installed Programs
$systeminfo.Programs = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,
                      HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName -ne $null} |
                      Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, EstimatedSize |
                      Sort-Object DisplayName

#Collect Windows Updates available
$UpdateSession = New-Object -ComObject Microsoft.Update.Session
$UpdateSearcher = $UpdateSession.CreateupdateSearcher()
$UpdateResults = @($UpdateSearcher.Search("IsHidden=0 and IsInstalled=0").Updates)
if ($UpdateResults.Count -gt 0) {
    $UpdateStr = $UpdateResults | Select-Object Title,MsrcSeverity | ForEach-Object {
        $_.Title = $_.Title -replace "\n|`r|`n" , "" # replace string in a property
        $_                                           # output the object back onto the pipeline
    }
    $systeminfo.WindowUpdates = $UpdateStr
}

#Collect Plesk Info
$pleskfile = $env:plesk_dir + "version";
if (Test-Path $pleskfile -PathType Leaf ) {
    $systeminfo.Plesk = & cat "$pleskfile" | Out-String -Stream | ForEach-Object { $_.Trim() }    
} else {
    $systeminfo.Plesk = '';
}


# Get a list of all users in the server
#$systeminfo.Users = Get-LocalUser | Select-Object Name, Description, Enabled, LastLogon, ObjectClass

# Get IP Addresses
$systeminfo.IpAddresses = Get-NetIPAddress | Where-Object {$_.AddressFamily -eq "IPv4" -and $_.InterfaceAlias -ne "Loopback Pseudo-Interface 1"} | Select-Object IPAddress

# Get Uptime
$uptime = (Get-Date) - (gcim Win32_OperatingSystem).LastBootUpTime
$systeminfo.Uptime = [Math]::Round($uptime.TotalSeconds)

# Get Current Timestamp
$systeminfo.Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

#Convert the hash table to JSON format
$jsonFile = "C:\SystemInformation.json"
$systeminfo | ConvertTo-Json | Out-File -FilePath $jsonFile

$url = "https://systemditor.com/upload.php"
$fileContent = Get-Content $jsonFile

$username = "ansible"
$password = "16ef4c840068267820ccdce99c9b05b6079ca413b9e1d7982b15684034467729"
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($username, $securePassword)

$headers = @{
    Authorization = 'Basic ' + [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($credential.GetNetworkCredential().Username + ':' + $credential.GetNetworkCredential().Password))
}

Invoke-RestMethod -Method POST -Uri $url -Headers $headers -ContentType "application/json" -Body $fileContent