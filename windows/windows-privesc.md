# Windows Privilege Escalation

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

### ACL / ACE

In Windows, there are multiple objects: 

* Files / Directories 
* Registry Entries 
* Services 

The access control list for a resource determines whether a user or group has permission to perform a specific action on it \(ACL\). The resource's access control list decides whether or not a person or group has authorization to perform a given action on it \(ACL\).

There are zero or more access control items in each ACL \(ACEs\). Each ACE establishes a link between a principal \(such as a user or a group\) and a specific access privilege.

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







