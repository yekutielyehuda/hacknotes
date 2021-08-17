# Local File Inclusion \(LFI\)

### Wrappers

{% embed url="https://www.php.net/manual/en/wrappers.php" %}

## Bypass Extensions Filters

%00 = Null bytes terminate the string, this trick can be used to bypass file extensions added server-side and are useful for file inclusions because it prevents the file extension from being considered as part of the string. 

? = The question mark, marks anything added to the URL server-side as part of the query string. It can also use be used as an "alternative" to the null bytes trick.

