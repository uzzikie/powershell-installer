$taskName = "Collect SystemInfo"
$taskScript = "$directoryPath\agent.ps1"
$task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue

if ($task -ne $null) {
    #Write-Host "The scheduled task $taskName exists."
}
else {
    # Install scheduled task 
    # Create a new scheduled task action to download and run the script
    $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/uzzikie/powershell-installer/main/agent.ps1'))"

    # Create a new trigger to run the task daily at 12am
    $trigger = New-ScheduledTaskTrigger -Daily -At 12am

    # Register the scheduled task with the Task Scheduler
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -User "SYSTEM" -RunLevel Highest  
}


