# Passive Information Gathering

## OSINT Framework

Look up information from almost everywhere:

{% embed url="https://osintframework.com/" %}

## Maltego

Collect information and create diagrams as you go:

{% embed url="https://www.maltego.com/" %}

## theHarverster

Gather information from a public domain using all available search engines:

```text
theHarvester -d domain.com -b all
```

Gather information from a public domain using multiple search engines:

```text
theHarvester -d domain.com -b google,trello,bing,dogpile
```

Gather information from a public domain using google:

```text
theHarvester -d domain.com -b google
```

## GitHub Repositories

We can search for possible GitHub repositories of the target:

```text
<service> site:github.com
```

### GitHub/GitLab Leaks

{% embed url="https://github.com/michenriksen/gitrob" %}

{% embed url="https://github.com/zricethezav/gitleaks" %}

## Site Information

### Netcraft

{% embed url="https://www.netcraft.com/" %}

Google Chrome Extension

{% embed url="https://chrome.google.com/webstore/detail/netcraft-extension/bmejphbfclcpmpohkggcjeibfilpamia" %}

Firefox Extension

{% embed url="https://addons.mozilla.org/en-GB/firefox/addon/netcraft-toolbar/?utm\_source=addons.mozilla.org&utm\_medium=referral&utm\_content=search" %}

### Security Headers

Analyze HTTP Headers:

{% embed url="https://securityheaders.com/" %}

### SSL/TLS

Analyze SSL/TLS settings:

{% embed url="https://www.ssllabs.com/ssltest/" %}







## Site Specific Tools

### Social Media

Search for information from social media sites:

{% embed url="https://www.social-searcher.com/" %}

Twitter Information:

{% embed url="https://digi.ninja/projects/twofi.php" %}

LinkedIn Information:

{% embed url="https://github.com/initstring/linkedin2username" %}

## Code Leaks

### Pastebin

Some people share sensitive codes for the public:

```text
<topic> site:pastebin.com
```

