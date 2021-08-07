# Name Resolution

## Name Resolution \(Old way of translating IPs to hostnames\)

The name resolution file is not the same as a DNS but it performs the same action which is translating IP addresses with domain names, however, is not a DNS because it's a file, not a server role or service and it doesn't have the ability to configure DNS records. Think of it as a table that maps IP to hostnames. This is often used when translating multiple domains or virtual hosts in an intranet or perhaps a LAN network for our localhost or machine.

### Windows

In Windows the name resolution file is located here:

```text
C:\Windows\System32\drivers\etc\hosts
```

### Unix/Linux

In Unix based operating systems, the name resolution file is located here:

```text
/etc/hosts
```
