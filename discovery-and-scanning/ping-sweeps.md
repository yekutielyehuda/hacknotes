# Ping Sweeps

One liner Ping Sweep:

* Windows:

```powershell
for /L %i in (1,1,255) do @ping -n 1 -w 200 10.10.10.%i > nul && echo 10.10.10.%i is up.
```

* Linux:

```bash
#!/bin/bash

for i in {1..254}
do
    ip="10.10.10.$i"
    ping -c 1 $ip >/dev/null 2>&1 && echo -e "$ip is\e[32m UP \e[0m" || echo -e "$ip is\e[31m unreachable \e[0m" 
done
```
