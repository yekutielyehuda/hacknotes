# PowerShell-Fu

## PowerShell Basics

PowerShell is the successor to [command.com](https://en.wikipedia.org/wiki/COMMAND.COM), [cmd.exe](https://en.wikipedia.org/wiki/Cmd.exe), and [cscript](https://en.wikipedia.org/wiki/Windows_Script_Host). Initially released as a separate download, it is now built into all modern versions of Microsoft Windows. PowerShell syntax takes the form of verb-noun patterns implemented in [cmdlets](https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/cmdlet-overview?view=powershell-7.1).

Cmdlets are small scripts that follow a dash-separated Verb-Noun convention such as "Get-Process". 

### Verbs

* New- Creates a new resource
* Set- Modifies an existing resource
* Get- Retrieves an existing resource
* Read- Gets information from a source, such

  as a file

* Find- Used to look for an object
* Search- Used to create a reference to a

  resource

* Start- \(asynchronous\) begin an operation,

  such as starting a process

* Invoke- \(synchronous\) perform an operation

  such as running a command

### **Parameters**

Each verb-noun named cmdlet may have many parameters to control cmdlet functionality.

### **Objects**

The output of most cmdlets are objects that can be passed to other cmdlets and further acted upon. This becomes important in pipelining cmdlets. 

### Finding Cmdlets

To get a list of all available cmdlets:

```text
PS C:\> Get-Command
```

Get-Command supports filtering. To filter cmdlets on the verb set:

```text
PS C:\> Get-Command Set* 
PS C:\> Get-Command –Verb Set
```

Or on the noun process:

```text
PS C:\> Get-Command *Process 
PS C:\> Get-Command –Noun process
```

### Help 

To get help with help:

```text
PS C:\> Get-Help
```

To read cmdlet self-documentation:

```text
PS C:\> Get-Help <cmdlet>
```

Detailed help:

```text
PS C:\> Get-Help <cmdlet> -detailed
```

Usage examples:

```text
PS C:\> Get-Help <cmdlet> -examples
```

Full \(everything\) help:

```text
PS C:\> Get-Help <cmdlet> -full
```

Online help \(if available\):

```text
PS C:\> Get-Help <cmdlet> -online
```

### Aliases

Aliases provide short references to long commands. To list available aliases:

```text
PS C:\> Get-Alias
```

To expand an alias into a full name:

```text
PS C:\> alias <unknown alias>
PS C:\> alias gcm
```

### Pipelining, Loops, and Variables

Piping cmdlet output to another cmdlet:

```text
PS C:\> Get-Process | Format-List –property name
```

ForEach-Object in the pipeline \(alias %\):

```text
PS C:\> ls *.txt | ForEach-Object {cat $_}
```

Where-Object condition \(alias where or ?\):

```text
PS C:\> Get-Process | Where-Object {$_.name –eq "notepad"}
```

Generating ranges of numbers and looping:

```text
PS C:\> 1..10
PS C:\> 1..10 | % {echo "Hello!"}
```

Creating and listing variables:

```text
PS C:\> $tmol = 42
PS C:\> ls variable:
```

Examples of passing cmdlet output down the pipeline:

```text
PS C:\> dir | group extension | sort
PS C:\> Get-Service dhcp | StopService -PassThru | Set-Service -StartupType Disabled
```

## PowerShell Common Cmdlets

Get a directory listing \(ls, dir, gci\):

```text
PS C:\> Get-ChildItem
```

Copy a file \(cp, copy, cpi\):

```text
PS C:\> Copy-Item src.txt dst.txt
```

Move a file \(mv, move, mi\):

```text
PS C:\> Move-Item src.txt dst.txt
```

Find text within a file:

```text
PS C:\> Select-String –path c:\users\*.txt –pattern password
PS C:\> ls -r c:\users -file | %{Select-String -path $_ -pattern password}
```

Display file contents \(cat, type, gc\):

```text
PS C:\> Get-Content file.txt
```

Get present directory \(pwd, gl\):

```text
PS C:\> Get-Location
```

Get a process listing \(ps, gps\):

```text
PS C:\> Get-Process
```

Get a service listing:

```text
PS C:\> Get-Service
```

Formatting the output of a command \(Format-List\):

```text
PS C:\> ls | Format-List –property name
```

Paginating output:

```text
PS C:\> ls –r | Out-Host -paging
```

Get the SHA1 hash of a file:

```text
PS C:\> Get-FileHash -Algorithm SHA1 file.txt
```

Exporting output to CSV: 

```text
PS C:> Get-Process | Export-Csv procs.csv
```

Conduct a ping sweep:

```text
PS C:\> 1..255 | % {echo "10.10.10.$_";ping -n 1 -w 100 10.10.10.$_ | SelectString ttl}
```

Conduct a port scan:

```text
PS C:\> 1..1024 | % {echo ((new-object Net.Sockets.TcpClient).Connect("10.10.10.10",$_)) "Port $_ is open!"} 2>$null
```

Fetch a file via HTTP \(wget in PowerShell\):

```text
PS C:\> (New-Object System.Net.WebClient).DownloadFile("http://10.10.10.10/nc.exe","nc.exe")
```

Find all files with a particular name:

```text
PS C:\> Get-ChildItem "C:\Users\" -recurse -include *passwords*.txt
```

Get a listing of all installed Microsoft Hotfixes:

```text
PS C:\> Get-HotFix
```

Navigate the Windows registry:

```text
PS C:\> cd HKLM:\
PS HKLM:\> ls
```

List programs set to start automatically in the registry:

```text
PS C:\> Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\run
```

Convert string from ASCII to Base64:

```text
PS C:\>[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("PSFTW!"))
```

List and modify the Windows firewall rules:

```text
PS C:\> Get-NetFirewallRule –all
PS C:\> New-NetFirewallRule -Action Allow -DisplayName LetMeIn -RemoteAddress 10.10.10.25
```

## PowerShell Filtering

We can filter by lines using elements or an array:

```text
$fileContents = Get-Content .\filename.txt

#Second line:
$fileContents[1]

#Third line:
$fileContents[2]

#Sixth line:
$fileContents[5]
```

An alternative solution in which we don't have to use a variable can be this one:

```text
get-content "file.txt" | foreach-object {
  $data = $_ -split " "
  "{0} {1} {2} {3} {4} {5} {6} {7}" -f $data[2],$data[3],$data[0],$data[5],$data[1],
    $data[4],$data[6],$data[7]
}
```





