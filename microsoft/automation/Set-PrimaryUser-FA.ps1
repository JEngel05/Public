# Primary User Validation
# Created by James Engel - Inspired by Sean Bulger
# Required Function App Powershell Module:  Az.Accounts
# Required Function App Configuration Variables:  TenantID
<# 
Required permissions:
    "Device.Read.All",
    "User.Read.All",
    "DeviceManagementManagedDevices.Read.All",
    "DeviceManagementManagedDevices.PrivilegedOperations.All"
#> 
using namespace System.Net

# Input bindings are passed in via param block.
param($Request)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#region functions
function Get-AuthToken {
    <#
    .SYNOPSIS
        Retrieve an access token for the Managed System Identity.
    
    .DESCRIPTION
        Retrieve an access token for the Managed System Identity.
    #>
    Process {
        # Get Managed Service Identity details from the Azure Functions application settings
        $MSIEndpoint = $env:MSI_ENDPOINT
        $MSISecret = $env:MSI_SECRET

        # Define the required URI and token request params
        $APIVersion = "2017-09-01"
        $ResourceURI = "https://graph.microsoft.com"
        $AuthURI = $MSIEndpoint + "?resource=$($ResourceURI)&api-version=$($APIVersion)"

        # Call resource URI to retrieve access token as Managed Service Identity
        $Response = Invoke-RestMethod -Uri $AuthURI -Method "Get" -Headers @{ "Secret" = "$($MSISecret)" }

        # Construct authentication header to be returned from function
        $AuthenticationHeader = @{
            "Authorization" = "Bearer $($Response.access_token)"
            "ExpiresOn" = $Response.expires_on
        }
        # Handle return value
        return $AuthenticationHeader
    }
}#end function 


# Setting inital Status Code: 
$StatusCode = [HttpStatusCode]::OK

# Get TenantID from the function application configuration. 
$TenantID = $env:TenantID

# Extracting and processing inbound parameters to variables for matching
$InboundDeviceID= $Request.Body.AzureADDeviceID
$InboundTenantID = $Request.Body.AzureADTenantID
$ManagedDeviceID = $Request.Body.ManagedDeviceID
$InboundUserList = $Request.Body.UserHash


# Write to the Azure Functions log stream.
Write-Information "Inbound DeviceID $($InboundDeviceID)"
Write-Information "Inbound TenantID $($InboundTenantID)"
Write-Information "Environment TenantID $($TenantID)"
Write-Information "Inbound Intune DeviceID $($ManagedDeviceID)"


### Start Endpoint Verification
# Verify request comes from correct tenant
if($TenantID -eq $InboundTenantID){
    Write-Information "Request is comming from correct tenant"
    # Retrieve authentication token
    $Script:AuthToken = Get-AuthToken

    # Query graph for device verification - Requires "Device.Read.All" Permission
    $DeviceURI = "https://graph.microsoft.com/v1.0/devices?`$filter=deviceId eq '$($InboundDeviceID)'"
    $DeviceIDResponse = (Invoke-RestMethod -Method "Get" -Uri $DeviceURI -ContentType "application/json" -Headers $Script:AuthToken -ErrorAction Stop).value

    # Assign to variables for matching 
    $DeviceID = $DeviceIDResponse.deviceId  
    $DeviceEnabled = $DeviceIDResponse.accountEnabled    
    Write-Information "DeviceID $DeviceID"   
    Write-Information "DeviceEnabled: $DeviceEnabled"
    # Verify request comes from a valid device
    if($DeviceID -eq $InboundDeviceID){
        Write-Information "Request is coming from a valid device in Azure AD"
        if($DeviceEnabled -eq "True"){
            Write-Information "Requesting device is not disabled in Azure AD"                       
            $ValidSystem = $true
        }
        else{
            Write-Warning "Device is not enabled - Forbidden"
            $StatusCode = [HttpStatusCode]::Forbidden
            $ValidSystem = $false
        }
    }
    else{
        Write-Warning  "Device not in my Tenant - Forbidden"
        $StatusCode = [HttpStatusCode]::Forbidden
        $ValidSystem = $false
    }
}
else{
    Write-Warning "Tenant not allowed - Forbidden"
    $StatusCode = [HttpStatusCode]::Forbidden
    $ValidSystem = $false
}


### Fail automation if data is missing or the device is invalid

# If the device is not trusted, 'Push-OutputBinding' as forbidden.
if (-not($ValidSystem)) {
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = $StatusCode
    })
    throw "Device is not trusted"
}

# If the user data is empty, 'PushOutputBinding' as BadRequest
if (-not($InboundUserList)) {
    $body = "No User Data Received"
    $StatusCode = [HttpStatusCode]::BadRequest
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = $StatusCode
        Body = $body
    })
    throw "No User Data Received"
}



#### Start Primary User Evaluation

# Build a hashtable with user data received from the proactive remediation
$UserHash = @{}
Foreach ($name in $InboundUserList.keys) {
    $userHash[$name] = $InboundUserList.$name
}

# Measure the number of logon counts and find the highest 
$Vals = $UserHash.Values | Measure-Object -Minimum -Maximum
$TopUser = $UserHash.GetEnumerator() | Where-Object Value -eq $Vals.Maximum

# Set the top Name and Count based on the highest logon count in the hashtable
$TopName = $TopUser.Key
[decimal]$TopCount = $TopUser.Value

Write-Output "User with highest logon count is $TopName. Logon Count is $TopCount."

#Get managed device and check for primary user 
Write-Output "Managed Device ID is $ManagedDeviceID"
$IntuneUserURI = "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$ManagedDeviceID/users"

# Query Intune Device to identify the primary user and primary user ID of the device
# Requires DeviceManagementManagedDevices.Read.All
$IntuneUserObject = (Invoke-RestMethod -Method "Get" -Uri $IntuneUserURI -ContentType "application/json" -Headers $Script:AuthToken -ErrorAction Stop).value

$IntunePrimaryUser = $IntuneUserObject.UserPrincipalName
$IntunePrimaryUserId = $IntuneUserObject.id
Write-Output "The primary user currently assigned is $IntunePrimaryUser"
Write-Output "The Primary User ID is $IntunePrimaryUserId"


#If a primary user is set, check to see if primary user is in user hash; Get count of logons
If($IntunePrimaryUser){

    If($UserHash.ContainsKey($IntunePrimaryUser)){

        [decimal]$IntunePrimaryUserCount = $InboundUserList.$IntunePrimaryUser
		Write-Output "The current Intune primary user $IntunePrimaryUser has logged in $IntunePrimaryUserCount times."

    } Else {

		Write-Output "The current Intune primary user $IntunePrimaryUser is not found in user hash table. "

	}

    # If the primary user has not logged on, set the Intune Primary User Count to 0.5 as we cannot divide by 0
	If($null -eq $IntunePrimaryUserCount){

		[decimal]$IntunePrimaryUserCount = 0.5

	}

    #Compare # of user logons for highest user with current primary user; determine who primary user should be
    # The TopCount is the highest logged in user.  PrimaryCount is the current Intune Primary user and how many times they have logged in
    $UDAMultiplier = $TopCount/$IntunePrimaryUserCount
	
    Write-Output "UDA Multiplier is $UDAMultiplier"

} else {
    Write-Output "No Primary User set on the device in Intune"
}


# If there is no Intune Primary User or the top user has logged in 50% more than the current Intune primary user, update the primary user in Intune
If((-not($IntunePrimaryUser)) -or ($UDAMultiplier -ge 1.5)){
 
    $UserPrincipalName = $TopUser.Key
	Write-Output "User with highest count to be assigned."
	Write-Output "Primary user to be assigned is $UserPrincipalName"

	#Get AAD Id of primary user to assign
	Write-Output "Getting User ID"
	$UserURI= "https://graph.microsoft.com/beta/users/$UserPrincipalName"

    # Requires "User.Read.All" permissions
	$UserGraphCall = Invoke-RestMethod -Method "Get" -Uri $UserURI -ContentType "application/json" -Headers $Script:AuthToken -ErrorAction Stop
	$UserID = $UserGraphCall.id


	#Update Primary User on Managed Device
	#Create required variables
	Write-Output "Updating primary user on Intune Device ID $ManagedDeviceID. New Primary User is $UserPrincipalName, ID: $UserID"
	$PrimaryUserBody = @{ "@odata.id" = "https://graph.microsoft.com/beta/users/$UserId" } | ConvertTo-Json
	$PrimaryUserURI = "https://graph.microsoft.com/beta/deviceManagement/managedDevices('$ManagedDeviceID')/users/`$ref"


	# Update the Intune Primary User
    Invoke-RestMethod -Method "POST" -Uri $PrimaryUserURI -ContentType "application/json" -Headers $Script:AuthToken -Body $PrimaryUserBody -ErrorAction Stop
	
    # Send Success Response
    Write-Output "Primary User has been updated"
    $body = "Primary User has been Updated"
    $StatusCode = [HttpStatusCode]::OK
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = $StatusCode
        Body = $body
    })

} else {
    # Send Success Response
    Write-Output = "Primary user will not change."
    $body = "Primary user will not change."
    $StatusCode = [HttpStatusCode]::OK
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = $StatusCode
        Body = $body
    })
}