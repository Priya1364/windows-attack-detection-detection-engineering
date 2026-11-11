# ==========================================
# WINDOWS SOC AUTOMATED DETECTION SYSTEM
# SOC WEEK 2 - DAY 6
# ==========================================

$StartTime = (Get-Date).AddHours(-24)

$OutputFolder = ".\Logs"

Write-Host "======================================"
Write-Host " WINDOWS SOC DETECTION SYSTEM"
Write-Host "======================================"

# ------------------------------------------
# 1. FAILED LOGIN DETECTION - EVENT 4625
# ------------------------------------------

Write-Host "`n[1] Checking failed login events..."

$FailedEvents = @(
    Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        Id = 4625
        StartTime = $StartTime
    } -MaxEvents 500 -ErrorAction SilentlyContinue
)

$FailedResults = foreach ($Event in $FailedEvents) {

    [xml]$Xml = $Event.ToXml()
    $Data = @{}

    foreach ($Item in $Xml.Event.EventData.Data) {
        $Data[$Item.Name] = [string]$Item.'#text'
    }

    [PSCustomObject]@{
        TimeCreated = $Event.TimeCreated
        Username = $Data['TargetUserName']
        IPAddress = $Data['IpAddress']
        LogonType = $Data['LogonType']
    }
}

$FailedResults |
Export-Csv "$OutputFolder\SOC-Failed-Logins.csv" -NoTypeInformation

$BruteForceAlerts = @(
    $FailedResults |
    Where-Object {
        $_.IPAddress -and
        $_.IPAddress -notin @('-', '127.0.0.1', '::1')
    } |
    Group-Object IPAddress |
    Where-Object { $_.Count -ge 5 } |
    ForEach-Object {
        [PSCustomObject]@{
            RuleID = "RULE001"
            Alert = "Repeated Failed Login"
            SourceIP = $_.Name
            Count = $_.Count
            Severity = "High"
        }
    }
)

# ------------------------------------------
# 2. SUSPICIOUS PROCESS DETECTION - SYSMON 1
# ------------------------------------------

Write-Host "[2] Checking process creation events..."

$ProcessEvents = @(
    Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        Id = 1
        StartTime = $StartTime
    } -MaxEvents 500 -ErrorAction SilentlyContinue
)

$ProcessResults = foreach ($Event in $ProcessEvents) {

    [xml]$Xml = $Event.ToXml()
    $Data = @{}

    foreach ($Item in $Xml.Event.EventData.Data) {
        $Data[$Item.Name] = [string]$Item.'#text'
    }

    [PSCustomObject]@{
        TimeCreated = $Event.TimeCreated
        Image = $Data['Image']
        CommandLine = $Data['CommandLine']
        ParentImage = $Data['ParentImage']
        User = $Data['User']
    }
}

$ProcessResults |
Export-Csv "$OutputFolder\SOC-Process-Activity.csv" -NoTypeInformation

$ProcessPattern = '(?i)(-encodedcommand\b|-enc\s+[A-Za-z0-9+/=]+|-windowstyle\s+hidden|downloadstring|frombase64string)'

$ProcessAlerts = @(
    $ProcessResults |
    Where-Object {
        $_.CommandLine -match $ProcessPattern -and
        $_.CommandLine -notmatch '(?i)SOC-Week02'
    } |
    ForEach-Object {
        [PSCustomObject]@{
            RuleID = "RULE002"
            Alert = "Suspicious Process Activity"
            Process = $_.Image
            CommandLine = $_.CommandLine
            Severity = "High"
        }
    }
)

# ------------------------------------------
# 3. POWERSHELL DETECTION - EVENT 4104
# ------------------------------------------

Write-Host "[3] Checking PowerShell script events..."

$PowerShellEvents = @(
    Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-PowerShell/Operational'
        Id = 4104
        StartTime = $StartTime
    } -MaxEvents 500 -ErrorAction SilentlyContinue
)

$PowerShellResults = foreach ($Event in $PowerShellEvents) {

    [xml]$Xml = $Event.ToXml()
    $Data = @{}

    foreach ($Item in $Xml.Event.EventData.Data) {
        $Data[$Item.Name] = [string]$Item.'#text'
    }

    [PSCustomObject]@{
        TimeCreated = $Event.TimeCreated
        ScriptBlock = $Data['ScriptBlockText']
    }
}

$PowerShellResults |
Export-Csv "$OutputFolder\SOC-PowerShell-Activity.csv" -NoTypeInformation

$PowerShellPattern = '(?i)(downloadstring|frombase64string|invoke-expression\s+\$|start-bitstransfer|invoke-webrequest)'

$PowerShellAlerts = @(
    $PowerShellResults |
    Where-Object {
        $_.ScriptBlock -match $PowerShellPattern -and
        $_.ScriptBlock -notmatch '(?i)SOC Week 2|Detect-PowerShellActivity|SOC-Automated-Detection|Day4-Test'
    } |
    ForEach-Object {
        [PSCustomObject]@{
            RuleID = "RULE003"
            Alert = "Potentially Suspicious PowerShell Activity"
            ScriptBlock = $_.ScriptBlock
            Severity = "Medium"
        }
    }
)

# ------------------------------------------
# 4. COMBINE ALL ALERTS
# ------------------------------------------

Write-Host "[4] Generating consolidated alerts..."

$AllAlerts = @(
    $BruteForceAlerts
    $ProcessAlerts
    $PowerShellAlerts
)

$AllAlerts |
Export-Csv "$OutputFolder\SOC-Final-Alerts.csv" -NoTypeInformation

# ------------------------------------------
# 5. GENERATE SUMMARY
# ------------------------------------------

$Summary = @(
    [PSCustomObject]@{
        Category = "Failed Login Events"
        Count = $FailedResults.Count
    }

    [PSCustomObject]@{
        Category = "Process Events"
        Count = $ProcessResults.Count
    }

    [PSCustomObject]@{
        Category = "PowerShell Events"
        Count = $PowerShellResults.Count
    }

    [PSCustomObject]@{
        Category = "Potential Security Alerts"
        Count = $AllAlerts.Count
    }
)

$Summary |
Export-Csv "$OutputFolder\SOC-Summary.csv" -NoTypeInformation

Write-Host "`n======================================"
Write-Host " SOC INVESTIGATION SUMMARY"
Write-Host "======================================"

$Summary | Format-Table -AutoSize

Write-Host "`nFinal alerts generated: $($AllAlerts.Count)"
Write-Host "Reports saved in Logs folder."
Write-Host "======================================"