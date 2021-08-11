# Web Fingerprinting

## Identify Web Technologies

### Headers

**Server:** \(IIS,Apache,Nginx,Others\) 

**X-Powered-By:** \(PHP,ASP.NET,JSP,JBoss,Others\) 

**Cookies:** \(PHPSESSID=XXXX, ASPSESSIONIDYYYY=XXXX, JSESSION=XXXX\)

Enumerate headers with curl:

```text
curl -I <IP>
```

Enumerate headers with nc:

```text
nc <IP> <PORT>

> Once we establish the connection with netcat

Type HEAD / HTTP/1.0 and hit enter two times
```

### Whatweb

Whatweb is a really good tool for web enumeration, we can use -v for a more readable output:

```text
whatweb -v <IP>
```

### Wappalyzer

Wapplyzer is a good browser extension for identifying web technologies:

{% embed url="https://addons.mozilla.org/en-GB/firefox/addon/wappalyzer/" %}



