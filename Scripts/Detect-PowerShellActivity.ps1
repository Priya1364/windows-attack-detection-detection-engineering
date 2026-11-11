# SOC Week 2 - Day 4
# PowerShell Activity Detection

$StartTime = (Get-Date).AddHours(-24)

$Events = Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-PowerShell/Operational'
    Id = 4104
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
        EventID     = $Event.Id
        ScriptBlock = $Data['ScriptBlockText']
        ScriptID    = $Data['ScriptBlockId']
    }
}

$Results | Export-Csv ".\Logs\PowerShell-Activity.csv" -NoTypeInformation

$Pattern = '(?i)(encodedcommand|downloadstring|frombase64string|invoke-expression|hidden|executionpolicy\s+bypass)'

$Alerts = $Results | Where-Object {
    $_.ScriptBlock -match $Pattern -and
    $_.ScriptBlock -notmatch '(?i)SOC-Week02|Detect-PowerShellActivity|Detect-SuspiciousProcesses|Day4-Test'
}

$Alerts | Export-Csv ".\Logs\PowerShell-Alerts.csv" -NoTypeInformation

Write-Host "===================================="
Write-Host "POWERSHELL ACTIVITY DETECTION"
Write-Host "===================================="
Write-Host "Total PowerShell events: $($Results.Count)"
Write-Host "Potential suspicious events: $($Alerts.Count)"

$Alerts | Format-Table TimeCreated, EventID, ScriptBlock -Wrap