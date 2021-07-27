# TFTP/Bittorrent-tracker - 69/UDP

## TFTP Information <a id="basic-information"></a>

**TFTP** uses UDP port 69 and **requires no authentication**—clients read from, and write to servers using the datagram format outlined in RFC 1350. Due to deficiencies within the protocol \(namely lack of authentication and no transport security\), it is uncommon to find servers on the public Internet. Within large internal networks, however, TFTP is used to serve configuration files and ROM images to VoIP handsets and other devices.

**Default Port:** 69/UDP

```text
PORT   STATE SERVICE REASON
69/udp open  tftp    script-set
```

## Enumeration <a id="enumeration"></a>

TFTP doesn't provide directory listing so the script `tftp-enum` from `nmap` will try to brute-force default paths.

```text
nmap -n -Pn -sU -p69 -sV --script tftp-enum <IP>
```

