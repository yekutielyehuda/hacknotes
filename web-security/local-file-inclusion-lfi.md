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

{% embed url="https://www.php.net/manual/en/wrappers.php" %}

## Bypass Extensions Filters

%00 = Null bytes terminate the string, this trick can be used to bypass file extensions added server-side and are useful for file inclusions because it prevents the file extension from being considered as part of the string. 

? = The question mark, marks anything added to the URL server-side as part of the query string. It can also use be used as an "alternative" to the null bytes trick.

