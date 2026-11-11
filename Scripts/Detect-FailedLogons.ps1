# Windows Failed Login Detection
# SOC Week 2 - Day 2

$StartTime = (Get-Date).AddHours(-24)

$Events = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4625
    StartTime = $StartTime
} -ErrorAction SilentlyContinue

$Results = foreach ($Event in $Events) {

    [xml]$Xml = $Event.ToXml()
    $Data = @{}

    foreach ($Item in $Xml.Event.EventData.Data) {
        $Data[$Item.Name] = [string]$Item.'#text'
    }

    [PSCustomObject]@{
        TimeCreated = $Event.TimeCreated
        Username    = $Data['TargetUserName']
        IPAddress   = $Data['IpAddress']
        Workstation = $Data['WorkstationName']
        LogonType   = $Data['LogonType']
        Status      = $Data['Status']
    }
}

$Results | Export-Csv ".\Logs\Failed-Login-Report.csv" -NoTypeInformation

$Alerts = $Results |
    Where-Object { $_.IPAddress -and $_.IPAddress -ne '-' } |
    Group-Object IPAddress |
    Where-Object { $_.Count -ge 5 } |
    Select-Object @{
        Name = 'SourceIP'
        Expression = { $_.Name }
    }, @{
        Name = 'FailedAttempts'
        Expression = { $_.Count }
    }

$Alerts | Export-Csv ".\Logs\BruteForce-Alerts.csv" -NoTypeInformation

Write-Host "===================================="
Write-Host "WINDOWS FAILED LOGIN DETECTION"
Write-Host "===================================="
Write-Host "Total failed login events: $($Results.Count)"
Write-Host "Potential brute-force alerts: $($Alerts.Count)"

if ($Alerts.Count -gt 0) {
    $Alerts | Format-Table -AutoSize
}
else {
    Write-Host "No source IP reached the detection threshold."
}