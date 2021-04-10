# CARTP-cheatsheet
Azure AD cheatsheet for the CARTP course

## General information
### Terminology
- Tenant - An instance of Azure AD and represents a single organization.
- Azure AD Directory - Each tenant has a dedicated Directory. This is used 
to perform identity and access management functions for resources. 
- Subscriptions - It is used to pay for services. There can be multiple 
subscriptions in a Directory.
- Core Domain - The initial domain name <tenant>.onmicrosoft.com is 
the core domain. it is possible to define custom domain names too.
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

# Enumeration
### Manually
#### Get tenant name and fedaration (If azure tenant is in use)
```
https://login.microsoftonline.com/getuserrealm.srf?login=<USER@DOMAIN>.com&xml=1
https://login.microsoftonline.com/getuserrealm.srf?login=root@defcorphq.onmicrosoft.com&xml=1
```

#### Get the Tenant ID
```
https://login.microsoftonline.com/<DOMAIN>/.well-known/openid-configuration
https://login.microsoftonline.com/defcorphq.onmicrosoft.com/.well-known/openid-configuration
```

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
https://github.com/NetSPI/MicroBurst
```
Import-Module MicroBurst.psm1 -Verbose
Invoke-EnumerateAzureSubDomains -Base defcorphq -Verbose
```

# Initial access attacks
#### Password spray
- https://github.com/dafthack/MSOLSpray
- https://github.com/ustayready/fireprox
```
Invoke-MSOLSpray -UserList C:\AzAD\Tools\validemails.txt -Password SuperVeryEasytoGuessPassword@1234 -Verbose
```

# Authenticated enumeration
## Enumeration through Azure portal
#### Login azure portal
Login to the azure portal with successfull attacks https://portal.azure.com/

#### Enumerate users, groups, devices, directory roles, enterprise applications
- Open the left menu --> Azure Active directory and click check the users, groups, Roles and administrators, Enterprise Application and devices tab.

## Enumeration AzureAD Module
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

#### Search attributes for all uers that contain the string "password" 
```
Get-AzureADUser |%{$Properties =
$_;$Properties.PSObject.Properties.Name | % {if
($Properties.$_ -match 'password') 
{"$($Properties.UserPrincipalName) - $_ -
$($Properties.$_)"}}}
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

# Privilege escalation
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

