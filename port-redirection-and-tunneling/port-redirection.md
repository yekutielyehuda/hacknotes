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





###  <a id="vpn-tunnel"></a>

