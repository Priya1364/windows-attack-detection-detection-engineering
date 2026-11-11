# SOC Week 2 - Day 3
# Suspicious Process Detection

$StartTime = (Get-Date).AddHours(-24)

$Events = Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id = 1
    StartTime = $StartTime
} -MaxEvents 500 -ErrorAction SilentlyContinue

$Results = foreach ($Event in $Events) {

    [xml]$Xml = $Event.ToXml()
    $Data = @{}

    foreach ($Item in $Xml.Event.EventData.Data) {
        $Data[$Item.Name] = [string]$Item.'#text'
    }

    [PSCustomObject]@{
        TimeCreated = $Event.TimeCreated
        Image       = $Data['Image']
        CommandLine = $Data['CommandLine']
        ParentImage = $Data['ParentImage']
        User        = $Data['User']
        ProcessId   = $Data['ProcessId']
    }
}

$Results | Export-Csv ".\Logs\Process-Activity.csv" -NoTypeInformation

$Pattern = '(?i)(-encodedcommand\b|-enc\b|-windowstyle\s+hidden|-executionpolicy\s+bypass|downloadstring|frombase64string|invoke-expression|https?://)'

$Alerts = $Results | Where-Object {
    $_.CommandLine -match $Pattern
}

$Alerts | Export-Csv ".\Logs\Suspicious-Process-Alerts.csv" -NoTypeInformation

Write-Host "===================================="
Write-Host "SUSPICIOUS PROCESS DETECTION"
Write-Host "===================================="
Write-Host "Total process events: $($Results.Count)"
Write-Host "Potential suspicious events: $($Alerts.Count)"

$Alerts | Format-Table TimeCreated, Image, CommandLine -Wrap