# XML External Entity \(XXE Injection\)

## XXE Information

XML external entity injection \(also known as XXE\) is a vulnerability that allows an attacker to interfere with an application's processing of XML data. It often allows an attacker to view files on the application server filesystem, and to interact with any back-end or external systems that the application itself can access.

### XXE

Some applications use the XML format to transmit data between the browser and the server. To process the XML data on the server, applications almost generally employ a common library or platform API. Because the XML specification provides a number of potentially harmful features, and standard parsers support these features even if they aren't used by the application, XXE vulnerabilities may exist.

External XML entities are a form of custom XML entity whose defined values are loaded from somewhere other than the DTD in which they are declared. External entities are intriguing from a security standpoint because they allow an entity to be defined depending on the contents of a file path or URL.

### XXE Types

* Exploiting XXE to retrieve files, where an external entity is defined containing the contents of a file, and returned in the application's response.
* Exploiting XXE to perform SSRF attacks, where an external entity is defined based on a URL to a back-end system.
* Exploiting blind XXE exfiltrate data out-of-band, where sensitive data is transmitted from the application server to a system that the attacker controls.
* Exploiting blind XXE to retrieve data via error messages, where the attacker can trigger a parsing error message containing sensitive data.

## XXE Enumeration

Manually testing for XXE vulnerabilities generally involves:

* Testing for file retrieval by defining an external entity based on a well-known operating system file and using that entity in data that is returned in the application's response.
* Testing for blind XXE vulnerabilities by defining an external entity based on a URL to a system that you control, and monitoring for interactions with that system.
* Testing for vulnerable inclusion of user-supplied non-XML data within a server-side XML document by using an XInclude attack to try to retrieve a well-known operating system file.

### XXE Example

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

## References

{% embed url="https://portswigger.net/web-security/xxe" %}



