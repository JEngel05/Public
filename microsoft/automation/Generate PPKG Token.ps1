#https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/how-to-retrieve-an-azure-ad-bulk-token-with-powershell/ba-p/2944894
#https://techcommunity.microsoft.com/t5/intune-customer-success/bulk-join-a-windows-device-to-azure-ad-and-microsoft-endpoint/ba-p/2381400

#Needs powershell 5
#Needs Image and Configuration Designer Installed
#User Generating the PPKG token requires permissions to join devices to Azure AD AND Enroll devices into MDM
#Token lasts 6 months.  Regenerate before it expires and update any provisioning automation.
#Creates an AAD User called BulkEnrollment_DateofTokenExpiration.  Exclude these from conditional access requiring MFA to join to Azure

Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process

#Requires -Modules AADInternals

# Start Function
function New-PPKG
{

[CmdletBinding()]
  Param(
      [Parameter(Mandatory=$true)]
      [ValidateNotNullOrEmpty()]
      [ValidateSet("QA", "Prod")]
      [string] $tenant
  )


#Set Environment
switch ($tenant) {
    "QA" {
            $script:ppkgtenant = "QA"
        }
     "Prod" {
            $script:ppkgtenant = "Prod"
        }
}


#set working directory
$workingdir = "C:\temp\ppkg"

#Create working Directory if it doesn't exist
if (-not(test-path $workingdir)) {
New-Item "C:\temp\ppkg" -ItemType Directory}

#Create directory for XML
if (-not(test-path $workingdir\temp)) {
New-Item "C:\temp\ppkg\temp" -ItemType Directory}


#Change to working directory
cd $workingdir

# Auth to Azure
# Uses need ability to "Register deviced" into AAD. Check Azure AD >Devices > Device Settings. Users may join devices to Azure AD needs to be "Selected" or "All"
Get-AADIntAccessTokenForAADGraph -Resource urn:ms-drs:enterpriseregistration.windows.net -SaveToCache

#set date and add expiration time for the ppkg
$date = (get-date).AddDays(180)
$date_friendly = $Date.ToString("yyyy_MM_dd")

# Create the new ppkg and use -expires to pass it a custom date/time
$bprt = New-AADIntBulkPRTToken -Name "BulkEnrollment_$date_friendly" -expires $date

#Windows Configuration Designer PPKG Details:
$packagepath = "$workingdir\AAD_Join_$($ppkgtenant)_$($date_friendly).ppkg"
$xmlpath = "$workingdir\temp\Customizations.xml"



function Get-IcdRoot {
    $regKey = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows Kits\Installed Roots"

    if (Test-Path -Path $regKey) {
        $kitsRoot = (Get-ItemProperty -Path $regKey).KitsRoot10

        if (!$kitsRoot) {
            return $null
        }

        $icdRoot = Join-Path -Path $kitsRoot -ChildPath 'Assessment and Deployment Kit\Imaging and Configuration Designer\x86'

        if (Test-Path -Path $icdRoot) {
            return $icdRoot
        }
    }

    return $null
}

# Create XML configurations

$CustomizationsXml = @"
<?xml version="1.0" encoding="utf-8"?>
<WindowsCustomizations>
  <PackageConfig xmlns="urn:schemas-Microsoft-com:Windows-ICD-Package-Config.v1.0">
    <ID>{1e4ed133-aae7-45f4-8ee1-881220aa52d5}</ID>
    <Name>AAD_Join_$($ppkgtenant)_$($date_friendly)</Name>
    <Version>1.0</Version>
    <OwnerType>OEM</OwnerType>
    <Rank>0</Rank>
    <Notes />
  </PackageConfig>
  <Settings xmlns="urn:schemas-microsoft-com:windows-provisioning">
    <Customizations>
      <Common>
        <Accounts>
          <Azure>
            <Authority>https://login.microsoftonline.com/common</Authority>
            <BPRT>$bprt</BPRT>
          </Azure>
        </Accounts>
      </Common>
    </Customizations>
  </Settings>
</WindowsCustomizations>
"@

# Create XML File
$CustomizationsXml | Out-File -FilePath $xmlpath -Encoding utf8 -Width 2000 -Force

# Set filepath for Image and Configuration Designer
$icdRoot= Get-IcdRoot

# Error if Image and Configuration Designer is not found
if (-not($icdRoot)) {
throw "Missing Image and Configuration Designer"}

$icdExec = Join-Path -Path $icdRoot -ChildPath 'ICD.exe'

# Create ppkg file
Start-Process $icdExec -ArgumentList "/Build-ProvisioningPackage /CustomizationXML:$xmlpath /PackagePath:$packagepath"
write-host "New PPKG file can be found at $packagepath"
} #End Function



## Uncomment the environment you need to generate a ppkg in

# Create QA PPKG
#New-PPKG -tenant QA

# Create PROD PPKG
#New-PPKG -tenant Prod
