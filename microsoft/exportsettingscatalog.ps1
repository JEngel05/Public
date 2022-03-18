# Requires Powershell 7
# Authenticate to Dev   
Get-GraphAppAuthToken -domain DEV # Use this function or any other means to get an OAuth Token.  Script uses $coreaccessd variable for the OAuth token

# Update these variables before running
$catalogname = "" # Name of the settings catalog to export
$JsonExport = "" # Set the location where you will export the Json File

#Microsoft Graph Variables
$Resource = "https://graph.microsoft.com/"
$betaversion = "beta"
$CPuri = "$resource$betaversion/deviceManagement/configurationPolicies"


#Store DEV Graph data into a variable.  This uses 2 different graph resources.
$CP = (Invoke-RestMethod -Uri $CPuri -Method Get -Authentication OAuth -Token $coreaccessd).value


if ($catalogname -in $CP.name) {
    Write-host "$($catalogname) Exists as a Settings Catalog in the configurationPolicies resource in DEV."

    # Acquire catalog ID
    $CPID = ($CP | Where-Object {$_.name -eq "$($catalogname)"}).id 

    #Export Settings Catalog metadata from DEV
    write-host "Attempting to export the profile metadata $($catalogname) with the id $($CPID) from DEV"
    $CPBase = Invoke-RestMethod -Uri "$CPuri/$CPID" -Method Get -Authentication OAuth -Token $coreaccessd
    
    # Looping through Odata results to build the settings data within the Catalog Settings object
    write-host "Attempting to query all settings from the catalog object $($CPBase.name)"
    $CPQuery = Invoke-RestMethod -Uri "$CPuri/$CPID/settings" -Method Get -Authentication OAuth -Token $coreaccessd
    $CPSettings = $CPQuery.value 
    if ($CPQuery.'@odata.nextLink') {
        do {
            #Query for the next page of results
            $CPQuery = Invoke-RestMethod -Uri $CPQuery.'@odata.nextLink' -Method Get -ErrorAction Stop -Token $coreaccessd -Authentication OAuth
            $CPSettings += $CPQuery.value
        }
        while ($CPQuery.'@odata.nextLink')
    }
    
    # Creating a new PSobject which contains the meta data and settings catalog data
    write-host "Attempting to build the settings catalog JSON Payload"
    $NewCP = [pscustomobject]@{
        name = "$($CPBase.name)"
        description = "$($CPBase.description)"
        platforms = "$($CPBase.platforms)"
        technologies = "$($CPBase.technologies)"
        # roleScopeTagIds = @('1') # Optional - set the scope tag.  Idenfity which number correlates to the specific scope tag you require before using. 
        settings = $CPSettings
    }

    # Convert the PSobject into JSON format
    $NewCPJson = $NewCP | ConvertTo-Json -depth 30
}

# Exports the Json to a file
$NewCPJson | Out-File -FilePath $JsonExport



<# The code in this block can be used to import the settings catalog data
#Acquire Test OAuth Token if necessary
if ($null -eq $coreaccesst) {
    write-host "Attempting to authenticate to Test"
    Get-GraphAppAuthToken -domain Test}    

# Push the settings catalog json data to Test
write-host "Attempting to push settings catalog JSON payload to Test"
Invoke-RestMethod -Uri $CPuri -Method Post -Body $NewCPJson -ContentType "application/json" -Authentication OAuth -Token $coreaccesst
#>
