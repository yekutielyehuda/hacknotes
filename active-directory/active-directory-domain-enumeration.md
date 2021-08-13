# Active Directory Domain Enumeration

## Active Directory Domain Enumeration

When enumerating an AD server from a client make sure the user you are logged in as a member of the AD.

## Active Directory Enumeration

### BloodHound

When we have to enumerate an Active Directory environment we should use the correct collector:

* AzureHound for Azure Active Directory
* SharpHound for local Active Directory

#### Azure Hound

```text
# require: Install-Module -name Az -AllowClobber
# require: Install-Module -name AzureADPreview -AllowClobber
Connect-AzureAD
Connect-AzAccount
. .\AzureHound.ps1
Invoke-AzureHound
```

**BloodHound**

Run the collector on the machine using SharpHound.exe [https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.exe](https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.exe) /usr/lib/bloodhound/resources/app/Collectors/SharpHound.exe

```text
.\SharpHound.exe -c all -d active.htb -SearchForest
.\SharpHound.exe --EncryptZip --ZipFilename export.zip
.\SharpHound.exe -c all,GPOLocalGroup
.\SharpHound.exe -c all --LdapUsername <UserName> --LdapPassword <Password> --JSONFolder <PathToFile>
.\SharpHound.exe -c all -d active.htb --LdapUsername <UserName> --LdapPassword <Password> --domaincontroller 10.10.10.10
.\SharpHound.exe -c all,GPOLocalGroup --outputdirectory C:\Windows\Temp --randomizefilenames --prettyjson --nosavecache --encryptzip --collectallproperties --throttle 10000 --jitter 23
```

Alternatively, run the collector on the machine using Powershell

```text
# https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.ps1
# /usr/lib/bloodhound/resources/app/Collectors/SharpHound.ps1
Invoke-BloodHound -SearchForest -CSVFolder C:\Users\Public
Invoke-BloodHound -CollectionMethod All
Invoke-BloodHound -CollectionMethod All  -LDAPUser <UserName> -LDAPPass <Password> -OutputDirectory <PathToFile>
```

Alternatively, remotely via BloodHound Python [https://github.com/fox-it/BloodHound.py](https://github.com/fox-it/BloodHound.py)

```text
pip install bloodhound
bloodhound-python -d lab.local -u rsmith -p Winter2017 -gc LAB2008DC01.lab.local -c all
bloodhound-python -d victim.local -u username -p "Password" -gc machine.victim.local -c all -ns 10.10.10.11
```

Then import the zip/json files into the Neo4J database and query them.

Alternatively, we can install bloodhound with the APT package manager:

```text
root@payload$ apt install bloodhound
```

Start BloodHound and the database

```text
root@payload$ neo4j console
```

Alternatively, use docker

```text
root@payload$ docker run -p7474:7474 -p7687:7687 -e NEO4J_AUTH=neo4j/bloodhound neo4j
```

Run bloodhound

```text
root@payload$ ./bloodhound --no-sandbox
```

Go to [http://127.0.0.1:7474](http://127.0.0.1:7474), use `db:bolt://localhost:7687`

The default credentials are user:neo4J, pass:neo4j

You can add some custom queries like Bloodhound-Custom-Queries from @hausec. Replace the customqueries.json file located at `/home/username/.config/bloodhound/customqueries.json` or `C:\Users\USERNAME\AppData\Roaming\BloodHound\customqueries.json`.

### PowerView

Get Current Domain:

```text
Get-NetDomain
```

Enumerate other Domains:

```text
Get-NetDomain -Domain <DomainName>
```

Get Domain SID:

```text
Get-DomainSID
```

Get Domain Policy:

```text
Get-DomainPolicy
```

Will show us the policy configurations of the Domain about system access or Kerberos

```text
(Get-DomainPolicy)."system access"
(Get-DomainPolicy)."kerberos policy"
```

#### Get Domain Controllers:

```text
Get-NetDomainController
Get-NetDomainController -Domain <DomainName>
```

#### Enumerate Domain Users:

```text
Get-NetUser
Get-NetUser -SamAccountName <user> 
Get-NetUser | select cn
Get-UserProperty
```

Check last password change

```text
Get-UserProperty -Properties pwdlastset
```

Get a specific "string" on a user's attribute

```text
Find-UserField -SearchField Description -SearchTerm "wtver"
```

Enumerate user logged on a machine

```text
Get-NetLoggedon -ComputerName <ComputerName>
```

Enumerate Session Information for a machine

```text
Get-NetSession -ComputerName <ComputerName>
```

Enumerate domain machines of the current/specified domain where specific users are logged into

```text
Find-DomainUserLocation -Domain <DomainName> | Select-Object UserName, SessionFromName
```

#### Enum**erate** Domain Computers:

```text
Get-NetComputer -FullData
Get-DomainGroup
```

#### Enumerate Live machines

```text
Get-NetComputer -Ping
```

#### Enum**erate** Groups and Group Members:

```text
Get-NetGroupMember -GroupName "<GroupName>" -Domain <DomainName>
```

Enumerate the members of a specified group of the domain

```text
Get-DomainGroup -Identity <GroupName> | Select-Object -ExpandProperty Member
```

Returns all GPOs in a domain that modify local group memberships through Restricted Groups or Group Policy Preferences

```text
Get-DomainGPOLocalGroup | Select-Object GPODisplayName, GroupName
```

#### Enumerate Shares

Enumerate Domain Shares

```text
Find-DomainShare
```

Enumerate Domain Shares the current user has access

```text
Find-DomainShare -CheckShareAccess
```

#### Enum**erate** Group Policies:

```text
Get-NetGPO
```

Shows active Policy on the specified machine

```text
Get-NetGPO -ComputerName <Name of the PC>
Get-NetGPOGroup
```

Get users that are part of a Machine's local Admin group

```text
Find-GPOComputerAdmin -ComputerName <ComputerName>
```

#### Enum**erate** OUs:

```text
Get-NetOU -FullData 
Get-NetGPO -GPOname <The GUID of the GPO>
```

#### Enum**erate** ACLs:

Returns the ACLs associated with the specified account

```text
Get-ObjectAcl -SamAccountName <AccountName> -ResolveGUIDs
Get-ObjectAcl -ADSprefix 'CN=Administrator, CN=Users' -Verbose
```

Search for interesting ACEs

```text
Invoke-ACLScanner -ResolveGUIDs
```

Check the ACLs associated with a specified path \(e.g smb share\)

```text
Get-PathAcl -Path "\\Path\Of\A\Share"
```

#### Enum**erate** Domain Trust:

```text
Get-NetDomainTrust
Get-NetDomainTrust -Domain <DomainName>
```

#### Enum**erate** Forest Trust:

```text
Get-NetForestDomain
Get-NetForestDomain Forest <ForestName>
```

Domains of Forest Enumeration

```text
Get-NetForestDomain
Get-NetForestDomain Forest <ForestName>
```

Map the Trust of the Forest

```text
Get-NetForestTrust
Get-NetDomainTrust -Forest <ForestName>
```

#### User Hunting

Finds all machines on the current domain where the current user has local admin access

```text
Find-LocalAdminAccess -Verbose
```

Find local admins on all machines of the domain:

```text
Invoke-EnumerateLocalAdmin -Verbose
```

Find computers where a Domain Admin OR a specified user has a session

```text
Invoke-UserHunter
Invoke-UserHunter -GroupName "RDPUsers"
Invoke-UserHunter -Stealth
```

Confirming admin access:

```text
Invoke-UserHunter -CheckAccess
```

### AD Module

**Get Current Domain:**

```text
Get-ADDomain
```

**Enumerate Other Domains:**

```text
Get-ADDomain -Identity <Domain>
```

**Get Domain SID:**

```text
Get-DomainSID
```

**Get Domain Controllers:**

```text
Get-ADDomainController
Get-ADDomainController -Identity <DomainName>
```

**Enumerate Domain Users:**

```text
Get-ADUser -Filter * -Identity <user> -Properties *
```

**Get a specific "string" on a user's attribute:**

```text
Get-ADUser -Filter 'Description -like "*wtver*"' -Properties Description | select Name, Description
```

**Enumerate Domain Computers:**

```text
Get-ADComputer -Filter * -Properties *
Get-ADGroup -Filter *
```

**Enumerate Domain Trust:**

```text
Get-ADTrust -Filter *
Get-ADTrust -Identity <DomainName>
```

**Enumerate Forest Trust:**

```text
Get-ADForest
Get-ADForest -Identity <ForestName>
```

**Domains of Forest Enumeration:**

```text
(Get-ADForest).Domains
```

**Enum Local AppLocker Effective Policy:**

```text
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

### Useful Enumeration Tools

* [ldapdomaindump](https://github.com/dirkjanm/ldapdomaindump) Information dumper via LDAP
* [adidnsdump](https://github.com/dirkjanm/adidnsdump) Integrated DNS dumping by any authenticated user
* [ACLight](https://github.com/cyberark/ACLight) Advanced Discovery of Privileged Accounts
* [ADRecon](https://github.com/sense-of-security/ADRecon) Detailed Active Directory Recon Tool

## References

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md" %}

{% embed url="https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet\#domain-enumeration" %}



