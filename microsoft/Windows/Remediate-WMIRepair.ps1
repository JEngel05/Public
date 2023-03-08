# Set log path
$logpath = "C:\Windows\Logs\Intune"
# Create c:\Windows\Logs\Intune if it does not exist
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
        $logFile = "$($logPath)\WMIRemediation.log"
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


# Set Variables
[array]$dll = Get-ChildItem -path c:\windows\system32\wbem | Where-Object Name -like *.dll 
[array]$exe = Get-ChildItem -path c:\windows\system32\wbem | Where-Object Name -like *.exe
[array]$mof = Get-ChildItem -path c:\windows\system32\wbem | Where-Object Name -like *.mof

# Reregistry wmi dll
foreach($item in $dll){
    Write-Log -Message $(@($item.fullname)) 
    regsvr32 /s $item.fullname
}

# Reregistry wmi exe
foreach($item in $exe){
    Write-Log -Message $(@($item.fullname)) 
    regsvr32 /s $item.fullname
}

# Recompile wmi mof
foreach($item in $mof){
    Write-Log -Message $(@($item.fullname)) 
    mofcomp $item.fullname
}


Stop-Service winmgmt -Force -PassThru
winmgmt /salvagerepository
winmgmt /resetrepository
Start-Service winmgmt -PassThru

 # Validate wmi repair
 $Bitlocker = Get-BitLockerVolume -MountPoint C:
If($Bitlocker) {
    Write-Log -Message "WMI Repair Successful.  C Drive is $($Bitlocker.VolumeStatus)"
} else {
    Write-Log -Level ERROR -Message "WMI Repair was Unsuccessful"
    Exit 1
}
