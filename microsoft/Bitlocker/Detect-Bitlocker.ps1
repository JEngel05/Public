# Detect script for Bitlocker

# Variables for Bitlocker on OS Drives
$bitlockerVolume = Get-BitLockerVolume C: # Get the Bitlocker information for C:\
$bitlockerVolumeStatus = $bitlockerVolume.VolumeStatus # Example result - FullyEncrypted
$bitlockerEncryptionPercent = $bitlockerVolume.EncryptionPercentage # Example result - 100
$bitlockerEncryptionMethod = $bitlockerVolume.EncryptionMethod # Example result - XtsAes256
$bitlockerProtectionStatus = $bitlockerVolume.ProtectionStatus # Example result - On
$bitlockerKeyProtectors = $bitlockerVolume.KeyProtector # Example result - All saved encryption keys
[array]$recoveyKeyProtectorIDs = ($bitlockerKeyProtectors | Where-Object {$_.KeyProtectorType -eq 'RecoveryPassword'}).KeyprotectorId # Example result - All saved "Recovery Password" encryption keys
$tpmKeyProtector = ($bitlockerKeyProtectors | Where-Object {$_.KeyProtectorType -eq 'Tpm'}) # Example result - All saved "TPM" encryption keys.  Validates that the TPM is in use.

# Setting a variable which finds all Fixed data drives
[array]$fixedVolumes = ((Get-Disk | Where-Object BusType -ne 'USB' | Get-Partition | Where-Object {($_.DriveLetter -ne "C") -and ($_.Type -eq "Basic")} | ForEach-Object { $_ | get-volume | Where-Object DriveLetter -ne $null }).DriveLetter)


# Set default remediation status to false
$remediate = $false

<# WMI Repair is being done in a separate Proactive Remediation
# Validate WMI
Try {
    Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop | Select-Object *
} catch {
    Write-Host "WMI entries for drive encryption are broken.  Flagging for Remediation"
    exit 1
}
#>

### OS Drive Encryption

# Verify Bitlocker OS Volume Exists
if (-not($bitlockerVolume)) {
    write-host "Bitlocker Volume on OS drive $($bitlockerVolume) is missing and drive is not encrypted.  Flagging for remediation"
    $remediate = $true
}

# Detect if the device is partially encrypted
if ($bitlockerEncryptionPercent -ne '100' -and $bitlockerEncryptionPercent -ne '0') {
    Write-Host "OS Drive Encryption is $($bitlockerEncryptionPercent) percent.  Flagging for remediation"
    $remediate = $true
}

# Detect if the OS Drive is not encrypted
if ($bitlockerEncryptionPercent -eq '0' -or $bitlockerVolumeStatus -eq 'FullyDecrypted') {
    Write-Host "OS Drive is not encrypted.  Flagging for remediation"
    $remediate = $true
}

# Detect if fully encrypted and protection is off
if ($bitlockerVolumeStatus -eq 'FullyEncrypted' -and $bitlockerProtectionStatus -eq 'off') {
    Write-Host "OS Drive is fully encrypted, but protection is turned off.  Flagging for remediation"
    $remediate = $true
}

# Detect if encryption is not AES256 or XTS-AES256
if (-not($bitlockerEncryptionMethod -eq 'XtsAes256' -or $bitlockerEncryptionMethod -eq 'Aes256')) {
    Write-Host "Encryption Type is configured as $($bitlockerEncryptionMethod).  This does not meet requirements. Flagging for remediation"
    $remediate = $true
}

# Detect if multiple key protectors are present
if ($recoveyKeyProtectorIDs.length -gt 1) {
    write-host "Multiple Protector IDs detected.  Flagging for remediation"
    $remediate = $true
    }

# Verify Bitlocker is using TPM
if (-not($tpmKeyProtector)) {
    write-host "No TPM key protector has been detected.  Flagging for remediation"
    $remediate = $true
}


### Data Drive Encryption

# Loop through all data bitlocker volumes as there may be multiple.  Check for encryption on each drive.
if ($fixedVolumes) {
    write-host "Fixed drive(s) detected."
    Foreach ($fixedVolume in $fixedVolumes) {

        # Query Bitlocker data on the fixed volume
        $BLData = Get-BitLockerVolume -MountPoint $fixedVolume
        write-host "Drive $($BLData.mountpoint) detected as a Fixed Drive.  Verifying Encryption Settings"

        # Check for Bitlocker Volume on the fixed drive
        if (-not($BLData)) {
            write-host "Bitlocker Volume on $($fixedVolume) is missing and drive is not encrypted.  Flagging for remediation"
            $remediate = $true
        }

        # Validate Fixed data drives for encryption status
        if ($BLData.EncryptionPercentage -eq '0' -or $BLData.VolumeStatus -eq 'FullyDecrypted') {
            write-host "Drive ($($BLData.mountpoint) is a Fixed drive and not encrypted.  Flagging for remediation"
            $remediate = $true
        }
        # Validate Fixed data drives have protection turned on
        if ($BLData.ProtectionStatus -eq 'off') {
            write-host "Drive ($($BLData.mountpoint) is a Fixed drive and protection is disabled.  Flagging for remediation"
            $remediate = $true
        }
        # Detect if encryption is not AES256 or XTS-AES256
        if (-not($BLData.encryptionMethod -eq 'XtsAes256' -or $BLData.encryptionMethod -eq 'Aes256')) {
            write-host "Drive ($($BLData.mountpoint) is a Fixed drive and does not meet cypher encryption strength.  Drive currently encrypted as $($BLData.encryptionMethod) .  Flagging for remediation"
            $remediate = $true
        }
    }
}

# If any detection has been flagged, remediate value will be set to true.  If true, exit 1 for remediation.
if ($remediate) {
    exit 1
}