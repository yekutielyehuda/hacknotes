# Proxychains

## Proxychains Fundamentals

Proxychains can significantly slow down a connection, and running a nmap scan over one is particularly painful. Whenever possible, you should strive to use static tools and only use proxychains when absolutely necessary.

Proxychains is a command-line tool that is started by typing proxychains before any other instructions. To proxy netcat through a proxy, for example, you may use the command:

```text
proxychains nc <IP> <PORT>
```

It's worth noting that the command above does not include a proxy port. Because proxychains read their parameters from a config file, this is the case. /etc/proxychains.conf is the master configuration file. By default, proxychains will look here; nevertheless, this is the last place that proxychains will look. The following are the locations \(in order\):

1. The current directory \(i.e. ./proxychains.conf\) 
2. ~/.proxychains/proxychains.conf 
3.  /etc/proxychains.conf

Simply run `cp /etc/proxychains.conf .` and make any necessary modifications to the config file in a copy in your current directory. If you're going to be moving directories a lot, you can put it in a proxychains directory under your home directory and get the same results. If the original master copy of the proxychains config is lost or destroyed, a replacement file can be found [here](https://raw.githubusercontent.com/haad/proxychains/master/src/proxychains.conf).

There is only one section of significant interest to us at this time: the proxy's servers, which are located near the bottom of the file. You can set up multiple servers here to chain proxies together, but for now, we'll stick with just one proxy:

```text
[ProxyList]
socks4    127.0.0.1    8080
```

There's one more line in the Proxychains setup that's worth noting, and that has to do with the Proxy DNS settings:

```text
# proxy_dns
```

The DNS should be commented out to avoid scanning problems.

> Note: Only TCP scans are allowed; UDP or SYN scans will fail. ICMP Echo packets \(Ping requests\) will likewise fail to pass through the proxy, thus use the -Pn flag to stop Nmap from attempting it.







