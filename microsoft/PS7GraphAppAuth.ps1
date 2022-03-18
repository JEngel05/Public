function Get-GraphAppAuthToken 
{
  <#
      .SYNOPSIS
      This function is used to authenticate with the Graph API REST interface using Powershell 7
      .DESCRIPTION
      The function authenticate with the Graph API using an Azure app registration and "Client Credentials" auth workflow
      .EXAMPLE
      Get-GraphAppAuthToken -domain Dev
      Get-GraphAppAuthToken -domain Test
      Get-GraphAppAuthToken -domain Prod
      .NOTES
      Authenticates you with the Graph API interface.
      $Authresultd, $Authresultt, $Authresultp contains the Oauth token.  You can view all the data of the OAuth token. 3 variables, one for each environment: Dev,Test,Prod.
      $Coreaccessd, $coreaccesst, $coreaccessp contains the secure string of the OAuth Access Token.  Use this for authentication.  3 variables, one for each environment: Dev,Test,Prod.
        Update the function with the clientID (App ID) with the Azure AD App registration you are using to authenticate.
        Update the function with the Tenant ID of the Azure App Registration
        Update the function with the "Secret" of each Azure AD App registration you are using to authenticate.  This goes in "Client_Secret"
  #>

[CmdletBinding()]
  Param(
      [Parameter(Mandatory=$true)]
      [ValidateNotNullOrEmpty()]
      [ValidateSet("Dev", "Test", "Prod")]
      [string] $domain
  )

$script:scope = "https://graph.microsoft.com/.default"

#Azure AD App Variables
switch ($domain) {
    "Dev" {
        $script:clientidd = "" #Update with the Azure App ID for Dev
        $script:tenantidd = "" #Update with the Azure Tenant ID for Dev
        $script:authurid = "https://login.microsoftonline.com/$tenantidd/oauth2/v2.0/token"
        
        $AuthBodyd = @{
            grant_type = 'client_credentials'
            scope = $script:scope
            client_id = $ClientIdd
            client_secret = "" # Update with the Dev client secret or use a secret management platform
        }
        #Acquire OAuth Token
        $script:authresultd = Invoke-RestMethod -uri $script:authurid -Method Post -Body $AuthBodyd
        #Convert Access Token to a secure string
        $script:coreaccessd = Convertto-securestring -string $authresultd.Access_Token -AsPlainText -Force
    }
    "Test" {
        $script:clientidt = "" # Update with the Azure App ID for Test
        $script:tenantidt = "" # Update with the Azure Tenant ID for Test
        $script:authurit = "https://login.microsoftonline.com/$tenantidt/oauth2/v2.0/token"
        
        $AuthBodyt = @{
            grant_type = 'client_credentials'
            scope = $script:scope
            client_id = $Clientidt
            client_secret = "" # Update with the Test client secret or use a secret management platform
        }
        #Acquire OAuth Token
        $script:authresultt = Invoke-RestMethod -uri $script:authurit -Method Post -Body $AuthBodyt
        #Convert Access Token to a secure string
        $script:coreaccesst = Convertto-securestring -string $authresultt.Access_Token -AsPlainText -Force
    }
    "Prod" {
        $script:clientidp = "" # Update with the Azure App ID for Prod
        $script:tenantidp = "" # Update with the Azure App ID for Prod
        $script:authurip = "https://login.microsoftonline.com/$tenantidp/oauth2/v2.0/token"
        
        $AuthBodyp = @{
            grant_type = 'client_credentials'
            scope = $script:scope
            client_id = $Clientidp
            client_secret = "" # Update with the Prod client secret or use a secret management platform
        }
        #Acquire OAuth Token
        $script:authresultp = Invoke-RestMethod -uri $script:authurip -Method Post -Body $AuthBodyp
        #Convert Access Token to a secure string
        $script:coreaccessp = Convertto-securestring -string $authresultp.Access_Token -AsPlainText -Force
    }
  }


####End Function
}
