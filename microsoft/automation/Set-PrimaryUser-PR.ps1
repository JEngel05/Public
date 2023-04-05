# Azure URL
$AzureFunctionURL = "" # Update with Function App URL
$filterDomain = "" # On Prem Domain Name
$FQDN = "" # Fully qualified domain name for Azure Tenant

# Enable TLS 1.2 support 
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Function to get Azure AD DeviceID
function Get-AzureADDeviceID {
    <#
    .DESCRIPTION
        Get the Azure AD device ID from the local device.
    #>
	Process {
		# Define Cloud Domain Join information registry path
		$AzureADJoinInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
		
		# Retrieve the child key name that is the thumbprint of the machine certificate containing the device identifier guid
		$AzureADJoinInfoKey = Get-ChildItem -Path $AzureADJoinInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
		if ($AzureADJoinInfoKey -ne $null) {
			# Retrieve the machine certificate based on thumbprint from registry key
            
            if ($AzureADJoinInfoKey -ne $null) {
                # Match key data against GUID regex
                if ([guid]::TryParse($AzureADJoinInfoKey, $([ref][guid]::Empty))) {
                    $AzureADJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Subject -like "CN=$($AzureADJoinInfoKey)" }
                }
                else {
                    $AzureADJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Thumbprint -eq $AzureADJoinInfoKey }    
                }
            }
			if ($AzureADJoinCertificate -ne $null) {
				# Determine the device identifier from the subject name
				$AzureADDeviceID = ($AzureADJoinCertificate | Select-Object -ExpandProperty "Subject") -replace "CN=", ""
				# Handle return value
				return $AzureADDeviceID
			}
		}
	}
} #endfunction 

#Function to get AzureAD TenantID
function Get-AzureADTenantID {
	# Cloud Join information registry path
	$AzureADTenantInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo"
	# Retrieve the child key name that is the tenant id for AzureAD
	$AzureADTenantID = Get-ChildItem -Path $AzureADTenantInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
	return $AzureADTenantID
} #endfunction                          

#Get Intune DeviceID and ManagedDeviceName
if (@(Get-ChildItem HKLM:SOFTWARE\Microsoft\Enrollments\ -Recurse | Where-Object { $_.PSChildName -eq 'MS DM Server' })) {
	$MSDMServerInfo = Get-ChildItem HKLM:SOFTWARE\Microsoft\Enrollments\ -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -eq 'MS DM Server'  }
	$ManagedDeviceInfo = Get-ItemProperty -LiteralPath "Registry::$($MSDMServerInfo)" -ErrorAction SilentlyContinue
	}

# Set Azure/MDM Device Information Variables
$ManagedDeviceID = $ManagedDeviceInfo.EntDMID # Intune Device ID
$AzureADDeviceID = Get-AzureADDeviceID # Azure AD Device ID
$AzureADTenantID = Get-AzureADTenantID # Azure Tenant ID


###### START DEVICE USER QUERY

#Filters for user logon events based on your domain and how far back to search the event log

$StartTime = (Get-Date).AddDays(-7)

#Hash table to filter for logon events in security log
$FilterHash = @{
  Logname='Security'
  ID='4624'
  StartTime=$StartTime
}

#Get all logon events from last 7 days
$LogHistory = Get-WinEvent -FilterHashtable $FilterHash | Select-Object TimeCreated,Properties

#Create empty users array
$Users =  @()

#Find user from each logon event
ForEach($Event in $LogHistory){
    
    # Property value "5" contains the username.  On AADJ systems it contains the domain name suffix.  On HAADJ systems it does not.  We confirm the HAADJ domain with value "6"
    $User = $Event.Properties[5].Value.ToString()
    $Domain = $Event.Properties[6].value.ToString()

    # ADD Users and exclude computer accounts that end with $ and exlucde svc accounts
    If(($Domain -eq "$FilterDomain") -and (-not($user.StartsWith("svc."))) -and (-not($user.EndsWith("$"))) ){
        # If the user has a FQDN suffix add to $users, otherwise append the FQDN before adding to ensure the same dataset between HAADJ and AADJ systems.
        If ($user -like "*$fqdn") {
        $Users += $User 
        } else 
        { 
        $Users += $User+"@$FQDN"
        } 
    }
}


$UserList = $Users | Group-Object | Select-Object Count, Name

$UserHash = @{}
$UserList | ForEach-Object { $UserHash[$_.Name] = $_.Count }

###### END DEVICE USER QUERY

# Construct main payload to send to the Azure Function
$MainPayLoad = [PSCustomObject]@{
	AzureADTenantID = $AzureADTenantID
	AzureADDeviceID = $AzureADDeviceID
    ManagedDeviceID = $ManagedDeviceID
	UserHash = $UserHash
}
# Convert payload to Json
$MainPayLoadJson = $MainPayLoad| ConvertTo-Json -Depth 9	

# Set default exit code to 0 
$ExitCode = 0

# Set Headers
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Content-Type", "application/json")


# Attempt to send data to API

try {
    $Response = Invoke-WebRequest $AzureFunctionURL -Method 'POST' -Headers $headers -Body $MainPayLoadJson -UseBasicParsing
    if ($response.StatusCode -eq "200"){
        $OutputMessage = "SUCCESS: $($response.StatusDescription): $($response.StatusCode) - $($response.content) "
        $ExitCode = 0
    } else {
        $OutputMessage = "FAIL: $($response.StatusDescription): $($response.StatusCode) - $($response.content) "
        $ExitCode = 1
    }
    } 
catch {
    $ResponseInventory = "Error Code: $($_.Exception.Response.StatusCode.value__)"
    $ResponseMessage = $_.Exception.Message
    $OutputMessage = "Validate Connectivity to Azure or Investigate Function App - $($ResponseInventory) + $($ResponseMessage) "
    $ExitCode = 1
}



# Exit script with correct output and code
Write-Output $OutputMessage
Exit $ExitCode	