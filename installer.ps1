# Check if Git is already installed
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    # Download Git installer
    $url = "https://github.com/git-for-windows/git/releases/download/v2.34.0.windows.1/Git-2.34.0-64-bit.exe"
    $output = "$env:USERPROFILE\Downloads\Git-2.34.0-64-bit.exe"
    Invoke-WebRequest -Uri $url -OutFile $output

    # Install Git silently
    $arguments = "/SILENT /NORESTART /SUPPRESSMSGBOXES /CLOSEAPPLICATIONS /RESTARTAPPLICATIONS"
    Start-Process -FilePath $output -ArgumentList $arguments -Wait
}

# Get the current path
$currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")

# Check if Git is already in the path
if ($currentPath -notlike "*C:\Program Files\Git\cmd*") {
    # Append Git to the path
    $newPath = "$currentPath;C:\Program Files\Git\cmd"
    [Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")
}

# Set the path of the directory to be created
$directoryPath = "C:\SystemInfo"

# Check if the directory already exists
if (-not (Test-Path $directoryPath)) {
    # Create the directory
    New-Item -ItemType Directory -Path $directoryPath
    git clone https://github.com/uzzikie/powershell-agent $directoryPath
    
} else {
    # Navigate to the repository directory and reset any changes
    cd $directoryPath
    git reset --hard
    git fetch --all
}


$taskName = "Collect SystemInfo"
$taskScript = "$directoryPath\agent.ps1"
$task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue

if ($task -ne $null) {
    #Write-Host "The scheduled task $taskName exists."
}
else {
    # Install scheduled task 
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File `"$taskScript`""
    $trigger = New-ScheduledTaskTrigger -Daily -At 12am

    # Register the scheduled task
    Register-ScheduledTask -TaskName $taskName -Trigger $trigger -Action $action -RunLevel Highest -User "SYSTEM"
  
}

