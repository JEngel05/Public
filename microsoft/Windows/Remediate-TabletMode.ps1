# THIS PR NEEDS TO BE RUN AS CURRENT USER
# Build Json of all registry settings.  Note, pay close attention to commas.  A comma is required after each line in objects, except for the last line.

$regJson = @"
[
    {
        description: "Enable Tablet Mode",
        path: "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\ImmersiveShell",
        name: "TabletMode",
        value: "1",
        type: "Dword"
    },
    {
        description: "Set SigninMode to Tablet",
        path: "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\ImmersiveShell",
        name: "SignInMode",
        value: "0",
        type: "Dword"
    }
]
"@


$regConfigs = $regJson | ConvertFrom-Json

# Validate all keys and entries exist.  Remediate any missing entries.

foreach ($regconfig in $regconfigs) {
    # Check the registry for the key and name and store the value in $regquery
    $regquery = Get-ItemProperty -Path "$($regconfig.path)" -ErrorAction Ignore | Select-Object -ExpandProperty $($regconfig.name) -ErrorAction Ignore

    # Check If the registry query and the expected registry value match.  If they don't match, fix the mismatch
    if ($($regquery) -eq $($regconfig.value)) {
        write-output "Found `"$($regconfig.path)`" with the entry `"$($regconfig.name)`" and the value `"$($regconfig.value)`""}
        else {
            $missingkey = "  Error detected with `"$($regconfig.path)`".  Registry entry `"$($regconfig.name)`" has an expected value of `"$($regconfig.value)`" and is missing or incorrect.  Attempting to remediate."
            $outputmsg += $missingkey
            if (Test-Path $regconfig.path) {
                # Push the correct registry entry and value
                $setkey = "  Attempting to set the registry entry `"$($regconfig.name)`" and value `"$($regconfig.value)`""
                New-ItemProperty -Path $regconfig.path -Name $regconfig.name -Value $regconfig.value -Type $regconfig.type -Force
                $outputmsg += $setkey
            } else {
                # If the key doesn't exist, create it first.  Then push the registry entry to the newly created key.
                $setkey = "  Creating registry key `"$($regconfig.path)`", setting the registry entry `"$($regconfig.name)`" and value `"$($regconfig.value)`""
                New-item -Path $regconfig.Path -Force
                New-ItemProperty -Path $regconfig.path -Name $regconfig.name -Value $regconfig.value -Type $regconfig.type -Force
                $outputmsg += $setkey
            }
        }
}


write-host $outputmsg