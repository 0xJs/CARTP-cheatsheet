# CARTP-cheatsheet
Azure AD cheatsheet for the CARTP course

# Sumarry
* [General](#General)
* [Recon](recon.md)
* [Initial access attacks](initial-access-attacks.md)
* [Authenticated enumeration](authenticated_enumeration.md)
* [Privilege Escalation](privilege_escalation.md)
* [Building Persistence](building-persistence.md)

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
