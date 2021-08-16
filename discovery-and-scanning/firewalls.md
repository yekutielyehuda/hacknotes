# Firewalls

## Unix/Linux

### iptables

View statistics of your iptables configuration:

```text
sudo iptables -vn -L

-v = verbose
-n = numeric output
-L = list rules present in chains
```

Modify or add a firewall rule:

```text
sudo iptables -I INPUT 1 -s 10.11.1.220 -j ACCEPT
sudo iptables -I OUTPUT 1 -d 10.11.1.220 -j ACCEPT
sudo iptables -Z
```

Flags and parameters:

* INPUT = inbound chain 
* OUTPUT = outbound chain 
* 1 = rule number 
* -s = source IP
* -d = destination IP
*  -j ACCEPT = allow traffic to pass 
* -Z = zero packet and byte counters in all chains

### ufw

Firewall status \(active\|inactive\):

```text
ufw status
```

Enable/Disable firewall:

```text
sudo ufw disable
sudo ufw enable
```

Firewall block denies from an IP address:

```text
sudo ufw deny from 203.0.113.100
```

Firewall block denies from a Subnet:

```text
sudo ufw deny from 203.0.113.0/24
```

Firewall block rule for a specific interface:

```text
sudo ufw deny in on eth0 from 203.0.113.100
```

Firewall rule that allows an IP address:

```text
sudo ufw allow from 203.0.113.101
```

Firewall rule that allows traffic from a specific interface:

```text
sudo ufw allow in on eth0 from 203.0.113.102
```

Firewall rules configuration:

```text
ufw status verbose
```

List firewall rules:

```text
ufw status numbered
```

Delete/remove a firewall with its number

```text
ufw delete NUM
```

## Windows

Windows Defender Firewall with Advanced Security

![Windows Defender Firewall](../.gitbook/assets/image%20%2821%29.png)

Windows Defender Firewall -&gt; Customise Settings

![Windows Defender Firewall - Customise Settings](../.gitbook/assets/image%20%2820%29.png)

## Network

### FortiGate

Visit the FortiGate documentation for detailed information:

{% embed url="https://docs.fortinet.com/" %}



