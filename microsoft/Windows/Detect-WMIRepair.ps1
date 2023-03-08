$remediate = $false
if (-not(get-disk)) {
    $outputmsg1 = " Invalid Disk Namespace"
    $remediate = $true
}

if (-not(Get-BitLockerVolume -MountPoint C:)) {
    $outputmsg2 = " Invalid Bitlocker Namespace"
    $remediate = $true
}

# Combine output messages into 1 line for better Intune reporting
$outputmsg = "$outputmsg1  $outputmsg2"

# Flag for Remediation if Necessary
if ($remediate) {
    write-host $outputmsg
    exit 1
} else {
    write-host "WMI is healthy"
    exit 0
}