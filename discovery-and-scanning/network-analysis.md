# Network Analysis

We can use `tcpdump` to perform an in-depth network analysis:

```bash
tcpdump -i eth0
tcpdump -c -i eth0
tcpdump -A -i eth0
tcpdump -w 0001.pcap -i eth0
tcpdump -r 0001.pcap
tcpdump -n -i eth0
tcpdump -i eth0 port 22
tcpdump -i eth0 -src 172.21.10.X
tcpdump -i eth0 -dst 172.21.10.X
```

