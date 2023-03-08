# Remediate script for Bitlocker
# Created by James Engel

# Set log path
$logpath = "C:\Windows\Logs\Intune"
# Create c:\temp\logs if it does not exist
if (-not(test-path $logpath)) {
New-Item -ItemType Directory -path "C:\Windows\Logs\Intune"}


Function Write-Log {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]
        $Message,
        [Parameter(Mandatory=$False)]
        [ValidateSet("INFO","WARN","ERROR","FATAL","DEBUG")]
        [String]
        $Level = "INFO",
        [Parameter(Mandatory=$False)]
        [string]
        $logFile = "$($logPath)\BLRemediation.log"
    )
    Try {
        $Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
        $Line = "$Stamp $Level $Message"
        If ($logfile) {
            Add-Content $logFile -Value $Line
        } Else {
            write-log $Line
        }
    } Catch {
        # Do Nothing
    }
}


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

# Set variables for querying Encryption profiles
$volume = Get-WMIObject -Namespace "root/CIMV2/Security/MicrosoftVolumeEncryption" -Class 'Win32_EncryptableVolume' -Filter "DriveLetter='C:'"
$TPMprotectorID = $volume.getkeyprotectors().VolumeKeyProtectorID | Where-Object {$volume.getkeyprotectortype($_).keyprotectortype -eq 1}

<# WMI Repair is being done in a separate Proactive Remediation
# Validate WMI
Try {
    Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop | Select-Object *
} catch {
    Write-Host "WMI entries for drive encryption are broken.  Attempting WMI Repair"
    Write-Log -Message "WMI entries for drive encryption are broken.  Attempting WMI Repair"
        mofcomp.exe "C:\Windows\System32\wbem\win32_encryptablevolume.mof"
        mofcomp.exe "C:\Windows\System32\wbem\cimwin32.mof"
        regsvr32.exe /s "c:\windows\system32\wbem\cimwin32.dll"
        Stop-Service Winmgmt -Force
        WinMgmt /salvagerepository
        WinMgmt /resetrepository
        Start-Service Winmgmt
        Write-Log -Message "Completed WMI repair."
}
#>
### OS Drive Encryption

# Verify Bitlocker OS Volume Exists
if (-not($bitlockerVolume)) {
    write-host "Bitlocker Volume on OS drive $($bitlockerVolume) is missing and drive is not encrypted."
    Write-Host "Initiating Intune Sync to enforce encryption policy and enable fixed drive encryption"
    Write-Log -Message "Bitlocker Volume on OS drive $($bitlockerVolume) is missing and drive is not encrypted."
    Write-Log -Message "Initiating Intune Sync to enforce encryption policy and enable fixed drive encryption"
    Get-ScheduledTask | Where-Object {$_.TaskName -eq "Schedule to run OMADMClient by client"} | Start-ScheduledTask
    Get-ScheduledTask | Where-Object {$_.TaskName -eq "PushLaunch"} | Start-ScheduledTask
    exit 0
}


# Detect and note if the device is partially encrypted
if ($bitlockerEncryptionPercent -ne '100' -and $bitlockerEncryptionPercent -ne '0') {
    Write-Host "OS Drive Encryption is $($bitlockerEncryptionPercent) percent.  If the issue persists, manual intervention is required"
    Write-Log -Message "OS Drive Encryption is $($bitlockerEncryptionPercent) percent.  If the issue persists, manual intervention is required"
    }

# If the OS Drive is not encrypted, initiate an Intune sync
if ($bitlockerEncryptionPercent -eq '0' -or $bitlockerVolumeStatus -eq 'FullyDecrypted') {
    Write-Host "OS Drive is not encrypted.  Initiating Intune Sync to enforce encryption policy"
    Write-Log -Message "OS Drive is not encrypted.  Initiating Intune Sync to enforce encryption policy"
    Get-ScheduledTask | Where-Object {$_.TaskName -eq "Schedule to run OMADMClient by client"} | Start-ScheduledTask
    Get-ScheduledTask | Where-Object {$_.TaskName -eq "PushLaunch"} | Start-ScheduledTask

<# Option 2:
    Write-Host "OS Drive is not encrypted.  Enabling BitLocker, TPM Protector and Recovery Password Protector"
    #$Enable-BitLocker -MountPoint $env:SystemDrive -EncryptionMethod XtsAes256 -UsedSpaceOnly -SkipHardwareTest -TPMProtector
	REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE" /V OSAllowedHardwareEncryptionAlgorithms /T REG_DWORD /D 0 /F
	REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE" /V EncryptionMethodWithXtsOs /T REG_DWORD /D 7 /F
	start-process "Manage-bde.exe" -ArgumentList "-on c: -recoverypassword -usedspaceonly -skiphardwaretest" -Wait
	Start-Sleep 5
    #Enable-BitLocker -MountPoint $env:SystemDrive -EncryptionMethod XtsAes256 -UsedSpaceOnly -SkipHardwareTest -RecoveryPasswordProtector
	$BLinfo = Get-Bitlockervolume -MountPoint $env:systemdrive | Select-Object *
	Write-Host "Current BL Status: $(@($blinfo.MountPoint)), $(@($blinfo.VolumeStatus)), $(@($blinfo.EncryptionMethod)),$(@($blinfo.KeyProtector))"

    # Save the newly created key to AAD
    BackupToAAD-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId $BLinfo.KeyProtector[1].KeyProtectorId
#>
}

# If fully encrypted and protection is off, Initiate an Intune sync
if ($bitlockerVolumeStatus -eq 'FullyEncrypted' -and $bitlockerProtectionStatus -eq 'off') {
    Write-Host "OS Drive is fully encrypted, but protection is turned off.  If validation Profiles are 7,11, re-enabling protection."
    Write-Log -Message "OS Drive is fully encrypted, but protection is turned off.  If validation Profiles are 7,11, re-enabling protection."
    if ($volume.GetKeyProtectorPlatformValidationProfile($TPMprotectorID).PlatformValidationProfile -match "7" -and $volume.GetKeyProtectorPlatformValidationProfile($TPMprotectorID).PlatformValidationProfile -match "11") {
        Write-Host "Initiating Intune Sync to enforce encryption policy and enable drive protection"
        Write-Log -Message "Initiating Intune Sync to enforce encryption policy and enable drive protection"
        Get-ScheduledTask | Where-Object {$_.TaskName -eq "Schedule to run OMADMClient by client"} | Start-ScheduledTask
        Get-ScheduledTask | Where-Object {$_.TaskName -eq "PushLaunch"} | Start-ScheduledTask
        <# Option 2      
        Write-Host "Turning Encryption Protection On"
        Resume-BitLocker -MountPoint $env:systemdrive
        #>
    }

}

# If encryption is not AES256 or XTS-AES256, Decrypt, Update registry keys, and Encrypt to XTSAES256
if (-not($bitlockerEncryptionMethod -eq 'XtsAes256' -or $bitlockerEncryptionMethod -eq 'Aes256')) {
    Write-Host "Encryption Type is configured as $($bitlockerEncryptionMethod).  Setting Encryption to XTSAES256"
    Write-Log -Message "Encryption Type is configured as $($bitlockerEncryptionMethod).  Setting Encryption to XTSAES256"
    start-process "Manage-bde.exe" -ArgumentList "-off c:" -Wait

    # Loop sleep until drive is unencrypted
    while (((Get-BitLockerVolume -MountPoint $env:SystemDrive).VolumeStatus) -eq "DecryptionInProgress") {
    start-sleep 5
    }
    # Set Registry keys for XTSAES256
    REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE" /V OSAllowedHardwareEncryptionAlgorithms /T REG_DWORD /D 0 /F
    REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE" /V EncryptionMethodWithXtsOs /T REG_DWORD /D 7 /F

    # Start Drive Encryption
    start-process "Manage-bde.exe" -ArgumentList "-on c: -recoverypassword -usedspaceonly -skiphardwaretest" -Wait
    
    # Sleep until Drive is Fully Encrypted
    Do {
        $encryptStatus = Get-Bitlockervolume -MountPoint $env:systemdrive | Select-Object *
        Write-Host "Current Encryption Status on $(@($encryptStatus.MountPoint)) $(@($encryptStatus.VolumeStatus)), $(@($encryptStatus.EncryptionPercentage)) percent encrypted"
        Write-Log -Message "Current Encryption Status on $(@($encryptStatus.MountPoint)) $(@($encryptStatus.VolumeStatus)), $(@($encryptStatus.EncryptionPercentage)) percent encrypted"
        Start-Sleep 30
    } Until (((Get-BitLockerVolume -MountPoint $env:SystemDrive).VolumeStatus) -eq "FullyEncrypted")
    
    # Query the final encryption status
    $BLinfo = Get-Bitlockervolume -MountPoint $env:systemdrive | Select-Object *
    Write-Host "Current BL Status: $(@($blinfo.MountPoint)), $(@($blinfo.VolumeStatus)), $(@($blinfo.EncryptionMethod)),$(@($blinfo.KeyProtector))"
    Write-Log -Message "Current BL Status: $(@($blinfo.MountPoint)), $(@($blinfo.VolumeStatus)), $(@($blinfo.EncryptionMethod)),$(@($blinfo.KeyProtector))"

    # Save the newly created key to AAD
    BackupToAAD-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId $BLinfo.KeyProtector[1].KeyProtectorId
}


# If multiple key protectors are present, Remove all keys except the first
if ($recoveyKeyProtectorIDs.length -gt 1) {
    write-host "Multiple Protector IDs detected.  Clearing extra keys"
    Write-Log -Message "Multiple Protector IDs detected.  Clearing extra keys"
    Foreach ($RecoveyKeyProtectorID in ($RecoveyKeyProtectorIDs | Select-Object -Skip 1)) {
        write-host "Removing Key ID $($RecoveyKeyProtectorID)"
        write-log -Message "Removing Key ID $($RecoveyKeyProtectorID)"
        Remove-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId $RecoveyKeyProtectorID
        }
    }

# Make note if Bitlocker is not using TPM
if (-not($tpmKeyProtector)) {
    write-host "No TPM key protector has been detected.  Manual intervention required"
    write-log -Message "No TPM key protector has been detected.  Manual intervention required"
}



### Data Drive Encryption

# If there are any non-usb Fixed volumes, loop through all data bitlocker volumes as there may be multiple.  Check for and remediate encryption on each drive.
if ($fixedVolumes) {
    write-host "Fixed drive(s) detected."
    write-log -Message "Fixed drive(s) detected."
    Foreach ($fixedVolume in $fixedVolumes) {

        # Query Bitlocker data on the fixed volume
        $BLData = Get-BitLockerVolume -MountPoint $fixedVolume
        write-host "Drive $($BLData.mountpoint) detected as a Fixed Drive.  Verifying Encryption Settings"
        write-log -Message "Drive $($BLData.mountpoint) detected as a Fixed Drive.  Verifying Encryption Settings"

        # Verify Bitlocker Fixed Drive Volume Exists
        if (-not($BLData)) {
            write-host "Bitlocker Volume on $($fixedVolume) is missing and drive is not encrypted."
            Write-Host "Initiating Intune Sync to enforce encryption policy and enable fixed drive encryption"
            Write-Log -Message "Bitlocker Volume on $($fixedVolume) is missing and drive is not encrypted."
            Write-Log -Message "Initiating Intune Sync to enforce encryption policy and enable fixed drive encryption"
            Get-ScheduledTask | Where-Object {$_.TaskName -eq "Schedule to run OMADMClient by client"} | Start-ScheduledTask
            Get-ScheduledTask | Where-Object {$_.TaskName -eq "PushLaunch"} | Start-ScheduledTask
            exit 0
        }

        # Validate Fixed data drives for encryption status.  Initiate Intune sync to fix any issues
        if ($BLData.EncryptionPercentage -eq '0' -or $BLData.VolumeStatus -eq 'FullyDecrypted') {
            write-host "Drive $($BLData.mountpoint) is a Fixed drive and not encrypted."
            Write-Host "Initiating Intune Sync to enforce encryption policy and enable fixed drive encryption"
            Write-Log -Message "Drive $($BLData.mountpoint) is a Fixed drive and not encrypted."
            Write-Log -Message "Initiating Intune Sync to enforce encryption policy and enable fixed drive encryption"
            Get-ScheduledTask | Where-Object {$_.TaskName -eq "Schedule to run OMADMClient by client"} | Start-ScheduledTask
            Get-ScheduledTask | Where-Object {$_.TaskName -eq "PushLaunch"} | Start-ScheduledTask
        }
        # Validate Fixed data drives have protection turned on, Initiate Intune sync to fix any issues
        if ($BLData.ProtectionStatus -eq 'off') {
            write-host "Drive $($BLData.mountpoint) is a Fixed drive and protection is disabled."
            Write-Host "Initiating Intune Sync to enforce encryption policy and enable fixed drive protection"
            Write-Log -Message "Drive $($BLData.mountpoint) is a Fixed drive and protection is disabled."
            Write-Log -Message "Initiating Intune Sync to enforce encryption policy and enable fixed drive protection"
            Get-ScheduledTask | Where-Object {$_.TaskName -eq "Schedule to run OMADMClient by client"} | Start-ScheduledTask
            Get-ScheduledTask | Where-Object {$_.TaskName -eq "PushLaunch"} | Start-ScheduledTask
        }
        # If fixed disk encryption is not AES256 or XTS-AES256, Decrypt, Update registry keys, and Encrypt to XTSAES256
        if (-not($BLData.encryptionMethod -eq 'XtsAes256' -or $BLData.encryptionMethod -eq 'Aes256')) {
            write-host "Drive $($BLData.mountpoint) is a Fixed drive and does not meet cypher encryption strength.  Drive currently encrypted as $($BLData.encryptionMethod).  Setting Encryption to XTSAES256"
            Write-Log -Message "Drive $($BLData.mountpoint) is a Fixed drive and does not meet cypher encryption strength.  Drive currently encrypted as $($BLData.encryptionMethod).  Setting Encryption to XTSAES256"
            start-process "Manage-bde.exe" -ArgumentList "-off $($BLData.mountpoint)" -Wait
        
            # Loop sleep until drive is unencrypted
            while (((Get-BitLockerVolume -MountPoint $BLData.mountpoint).VolumeStatus) -eq "DecryptionInProgress") {
            start-sleep 5
            }

            # Set Registry keys for XTSAES256 on Fixed Drives
            REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE" /V FDVAllowedHardwareEncryptionAlgorithms /T REG_DWORD /D 0 /F
            REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE" /V EncryptionMethodWithXtsFdv /T REG_DWORD /D 7 /F
            
            # Start Drive Encryption
            start-process "Manage-bde.exe" -ArgumentList "-on $($BLData.mountpoint) -recoverypassword -usedspaceonly -skiphardwaretest" -Wait
            
            # Sleep until Drive is Fully Encrypted
            Do {
                $encryptStatus = Get-Bitlockervolume -MountPoint $BLData.mountpoint | Select-Object *
                Write-Host "Current Encryption Status on fixed drive $(@($encryptStatus.MountPoint)) $(@($encryptStatus.VolumeStatus)), $(@($encryptStatus.EncryptionPercentage)) percent encrypted"
                Write-Log -Message "Current Encryption Status on fixed drive $(@($encryptStatus.MountPoint)) $(@($encryptStatus.VolumeStatus)), $(@($encryptStatus.EncryptionPercentage)) percent encrypted"
                Start-Sleep 30
            } Until (((Get-BitLockerVolume -MountPoint $BLData.mountpoint).VolumeStatus) -eq "FullyEncrypted")
            
            # Query the final encryption status
            $BLinfo = Get-Bitlockervolume -MountPoint $BLData.mountpoint | Select-Object *
            Write-Host "Current BL Status on Fixed Drive: $(@($blinfo.MountPoint)), $(@($blinfo.VolumeStatus)), $(@($blinfo.EncryptionMethod)),$(@($blinfo.KeyProtector))"
            Write-Log -Message "Current BL Status on Fixed Drive: $(@($blinfo.MountPoint)), $(@($blinfo.VolumeStatus)), $(@($blinfo.EncryptionMethod)),$(@($blinfo.KeyProtector))"

            # Save the newly created key to AAD
            $FDVKeyProtectorID = ($BLinfo.KeyProtector | Where-Object {$_.keyprotectortype -eq 'RecoveryPassword'}).KeyprotectorId
            BackupToAAD-BitLockerKeyProtector -MountPoint $BLData.mountpoint -KeyProtectorId $FDVKeyProtectorID
        }
    }
}
