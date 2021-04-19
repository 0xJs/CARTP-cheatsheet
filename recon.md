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
