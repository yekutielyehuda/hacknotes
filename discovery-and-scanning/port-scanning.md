# Port Scanning

## Port Scanning Methodology

Here is my simple but effective port scanning methodology.

### Proxy

If you are scanning through a proxy you must use -Pn and -sT flags since the TCP Handshake is not received by us. 

`-sT` will do a full TCP connect scan, rather than the default `-sS` SYN scan. An SYN scan won’t work because the proxy won't be passing the TCP handshake packets back to us, so an SYN scan, which sends the SYN packet, sees the ACK, and then ends the connection, won’t be passed back over the proxy. `-Pn` also necessary because the typical host detection `nmap` does involves sending ICMP and TCP on 80 and 443. ICMP won’t go over the proxy, and 80 and 443 are likely, not going to be open, so it just returns that the host is down. `-Pn` tells `nmap` to continue scanning without that check.

> The information above was extracted from [here](https://0xdf.gitlab.io/2021/06/19/htb-tentacle.html#recon).

TL;DR: proxy support is limited right now but there are also theoretical limits of what you could do when using a proxy.

nmap can do only CONNECT and SOCKS4 and these protocols can do only TCP. Apart from that using any kind of proxy means that nmap communicates with the IP stack of the proxy and not of the target. This means:

* ICMP ping can not be done to see if a host is alive, since ICMP is not TCP. So you might need to skip the host discovery step if your targets are only accessible through the proxy \(`-Pn`\). Since \(the unsupported\) SOCKS5 ICMP does not support ICMP either this will not change in the future.
* Service discovery can be done for TCP based services only. With SOCKS5 support this could be extended to UDP.
* OS fingerprinting based on features of the IP stack is not possible because nmap does not speak with the targets IP stack when using a proxy, but instead with the proxies IP stack. This is a theoretical limit you have with any kind of proxy protocol.

Extracted from here:

{% embed url="https://security.stackexchange.com/questions/120708/nmap-through-proxy" %}

### ICMP

#### Windows

ICMP may not always be enabled in Windows, in such case you will need to use `-Pn` in your nmap scans.

TTL -&gt; 127/8

```text
ping -n 1 <IP>
```

#### Nix

ICMP is enabled by default in Unix/Linux systems, in the case that is disabled, you will need to use `-Pn` in your nmap scans.

TTL -&gt; 64

```text
ping -c 1 <IP>
```

### Nmap Recon Methodology

After confirming that ICMP is enabled \(if disabled use -Pn\), I like to start up with an SYN Stealth scan on all ports scan with a high packet rate \(the min-rate can be high for a testing environment, **not** for a production environment\):

```text
nmap -sS -p- --min-rate 10000 -n -Pn -oG scans/nmap-alltcp 10.10.10.10
```

Then, I extract the open ports and scan those ports:

```text
nmap -sC -sV -n -Pn -p 22,135,139,445 -oA scans/nmap-tcpscripts 10.10.10.10
```

Second, I start UDP scan on the top 20 most common ports:

```text
nmap -sU --top-ports 20 -oG scans/nmap-udp-top20 10.10.10.10
```

### TCP Scanning

This is a good all-purpose initial scan. Scans the most common 1000 ports with service information \(-sV\), default scripts \(-sC\), and OS detection with \(-O\).

> Note: Verbose mode \(-v\) not only provides the estimated time for each host, but it also prints the results as it goes letting you continue with the reconnaissance while scanning.

```text
sudo nmap -v -sV -sC -O -T4 -n -Pn -oA nmap_scan 10.10.10.10
```

Similar scan but scans all ports, from 1 through 65535.

```text
sudo nmap -v -sV -sC -O -T4 -n -Pn -p- -oA nmap_fullscan 10.10.10.10
```

### UDP Scanning

During a UDP scan \(-Su\) -sV will send protocol-specific probes, also known as nmap-service-probes, to every open\|filtered port. In case of response the state change to open. 

```text
sudo nmap -sU -sV --version-intensity 0 -n 10.10.10.10
```

### Nmap Extract Ports

I have zsh function which extracts ports from a grep file, thanks to [S4vitar](https://www.youtube.com/channel/UCNHWpNqiM8yOQcHXtsluD7Q) for sharing this function.

```bash
xp4 () {
	ports="$(cat $1 | grep -oP '\d{1,5}/open' | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)"
	ip_address="$(cat $1 | grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' | sort -u | head -n 1)"
	echo -e "[*] IP Address: $ip_address" >> xp4.tmp
	echo -e "[*] Open ports: $ports\n" >> xp4.tmp
	echo $ports | tr -d '\n' | xclip -sel clip
	echo -e "[*] Ports copied to clipboard\n" >> xp4.tmp
	cat xp4.tmp
	rm xp4.tmp
}
```

Alternatively, we can extract ports like this:

```text
cat filename.nmap | grep open | awk -F/ '{print $1}' ORS=','; echo
nmap -p 80,443,3389 -sC -sV 10.10.10.111
```

### Nmap Scripts

List all Nmap scripts categories:

```text
grep -r categories /usr/share/nmap/scripts/.nse | grep -oP '".?"' | sort -u
```

List scripts under the **default** category:

```text
grep -r categories /usr/share/nmap/scripts/*.nse | grep default | cut -d: -f1
```

### Nmap Vulnerability Scan

Vulnerability scan with **vuln** scripts:

```text
nmap -sV --script vuln -oA vuln-scan 10.10.10.10
```

## Auto Reconnaissance Tools

### AutoRecon

One of the good tools out there for automatic recon is AutoRecon:

{% embed url="https://github.com/Tib3rius/AutoRecon" %}

### reconnoitre

```text
reconnoitre -t ip -o output_directorry --services
reconnoitre -t ip --services --quick -o output_directory
reconnoitre -t ip -o output_directory
```

### onetwopunch

```text
./onetwopunch.sh -t targets -p all -n "-sV -O --version-intensity=9"
```

### nmapAutomator

[https://github.com/21y4d/nmapAutomator](https://github.com/21y4d/nmapAutomator)

```text
./nmapAutomator.sh <TARGET-IP> <TYPE>
./nmapAutomator.sh 10.1.1.1 All 
./nmapAutomator.sh 10.1.1.1 Basic  
./nmapAutomator.sh 10.1.1.1 Recon
```

If you want to use it anywhere on the system, create a shortcut using:

```text
ln -s /PATH-TO-FOLDER/nmapAutomator.sh /usr/local/bin/
```

## Port Knocking

### Install Port Knock

1. `apt-get install knockd`
2. Then you simply type: `knock [ip] [port]`. For example: `knock ip 4000 5000 6000`
3. After that, you have to scan the network to see if any new port is open.
4. If you know what port is open you can connect to the port using Netcat. The following command would work `nc 192.168.1.102 8888`. This would then connect to the port.

### Nmap/Bash Open Port

```bash
for x in 4000 5000 6000; do nmap -Pn --host_timeout 201 --max-retries 0 -p $x server_ip_address; done
```




