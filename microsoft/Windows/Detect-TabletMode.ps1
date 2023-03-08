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

$remediate = $false
$regConfigs = $regJson | ConvertFrom-Json

# Validate all keys exist
foreach ($regconfig in $regconfigs) {
    $regquery = Get-ItemProperty -Path "$($regconfig.path)" | Select-Object -ExpandProperty $($regconfig.name)
    if ($($regquery) -eq $($regconfig.value)) {
        write-output "Found `"$($regconfig.path)`" with the entry `"$($regconfig.name)`" and the value `"$($regconfig.value)`""}
        else {
            $missingkey = "  Error detected with `"$($regconfig.path)`", `"$($regconfig.name)`". The value `"$($regconfig.value)`" is missing or incorrect."
            $remediate = $true
            $outputmsg += $missingkey
        }
}

if ($remediate) {
    write-host $outputmsg
    exit 1
} else {
    write-host "All registry keys exist"
    exit 0
}
