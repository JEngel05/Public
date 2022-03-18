function Get-GraphAuthToken 
{
  <#
      .SYNOPSIS
      This function is used to authenticate with the Graph API REST interface using Powershell 7
      .DESCRIPTION
      The function authenticates with the Graph API using an Azure app registration and "Authenciation Code" authorization flow.  Requires MSAL.PS Module.
      To install the module: Install-Module -Name MSAL.PS
      .EXAMPLE
      Get-GraphAuthToken -domain Dev
      Get-GraphAuthToken -domain Test
      Get-GraphAuthToken -domain Prod
      .NOTES
      Authenticates you with the Graph API interface.  This will prompt you to enter credentials which have access to the graph resources.
      $Authresult contains the Oauth token.  You can view all the data of the OAuth token.
      $Coreaccess contains the secure string of the OAuth Access Token.  Use this for authentication.
  #>

[CmdletBinding()]
  Param(
      [Parameter(Mandatory=$true)]
      [ValidateNotNullOrEmpty()]
      [ValidateSet("Dev", "Test", "Prod")]
      [string] $domain
  )


#Requires -Module MSAL.PS

#Azure AD App Variables
switch ($domain) {
    "Dev" {
        $script:clientid = "" # Update with the app ID of the Azure App Registration in Dev
        $script:tenantid = "" # Update with the tenant ID of the Azure App Registration in Dev
    }
    "Test" {
        $script:clientid = "" # Update with the app ID of the Azure App Registration in Test
        $script:tenantid = "" # Update with the tenant ID of the Azure App Registration in Test
    }
    "Prod" {
        $script:clientid = "" # Update with the app ID of the Azure App Registration in Prod
        $script:tenantid = "" # Update with the tenant ID of the Azure App Registration in Prod
    }
  }


#Use MSAL to acquire an OAuth Token using Authorization Code workflow
$script:authresult = Get-MsalToken -clientid $clientid -TenantId $tenantid

#Convert Access Token to a secure string
$script:coreaccess = Convertto-securestring -string $authresult.AccessToken -AsPlainText -Force

####End Function
}
