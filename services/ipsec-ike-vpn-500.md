# IPsec/IKE VPN - 500

## IKE Enumeration

A simple IKE scan can be as follows:

```text
ike-scan <IP>
```

Troubleshoot with strace:

```text
strace ike-scan <IP>
```

Check if there's another process using the port 500 with:

```text
lsof -i:500
```

Normally, charon could be running, kill the process:

```text
pkill charon
```

Scan IKE and save the output:

```text
ike-scan <IP> -M | tee output
```

## IKE Configuration

### strongswan

We can install strongswan using APT:

```text
apt install strongswan
```

The configuration file are the following:

```text
cat /etc/ipsec.secrets
cat /etc/ipsec.conf
```

### Example Configuration

The ipsec.conf file may look like the following in order to connect to IPsec:

```text
conn wixnic
    ike=3des-sha1-mod1024
    esp=3des-sha1
    type=transport
    auto=add # ondemand restart
    authby=secret
    keyexchange=ikev1
    left=YOUR_IP
    right=TARGET_IP
    rightsubment=TARGET_IP[tcp]
```

Then restart IPsec to apply the changes with:

```text
ipsec restart
```

Next, connect to the target:

```text
ipsec up wixnic
```



