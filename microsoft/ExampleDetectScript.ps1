$jsonpath = "C:\Temp\SiteZoneAssignment.json"
$regpath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMapKey"
$remediate = $false


# Validate file exists and has proper syntax.  Does NOT Validate registry values
try {
    $regConfigs = get-content -Path $jsonpath -ErrorAction Stop | ConvertFrom-Json
}
catch {
    write-host "$($error[0]).Exception.Message"
    throw "Invalid Json.  Verify syntax, commas, and that the file exists at $($jsonpath)"
}


# Validate all keys exist
foreach ($regconfig in $regconfigs) {
    $regquery = (Get-ItemProperty -path $regpath -ErrorAction SilentlyContinue).($regconfig.name)
    if ($regquery -eq $regconfig.value) {
        write-host "Found entry `"$($regconfig.name)`" which contains the value `"$($regconfig.value)`""}
        else {
            write-host "Error detected with the entry `"$($regconfig.name)`". Expected value of `"$($regconfig.value)`" is missing or incorrect.  Flagging for remediation."
            $Remediate = $true
        }
}

if ($Remediate) {
    exit 1
}
