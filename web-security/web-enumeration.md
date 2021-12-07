# Web Enumeration

## Inspecting Operating System

## Inspecting Certificate&#x20;

## Inspecting Virtual Hosting

## HTTP Headers

### User-Agent



#### ShellShock

### Response Headers

## Parameters

### GET Parameters

### POST Parameters

## Input

### Forms

### Comments

### Text Boxes

### Search Bars

## DevTools

### Sources

### Network&#x20;

### Storage&#x20;

## Administration Consoles | Control Panels

## Inspecting Sitemaps

## Inspecting Page Content

## Inspecting URLs

## Inspecting Databases

## Inspecting Frameworks

## Inspecting Software or Applications

## Web Fuzzing | Find Directories, Files, Subdomains, Virtual Hosting, Parameters, and Values

Check out this page:

{% embed url="https://wixnic.gitbook.io/hacknotes/web-security/web-fuzzing" %}

## Sensitive Files

Search **every** website and sub directory for interesting services or files containing potential usernames and/or passwords.

## Tools

### nikto

nikto is a good at finding stuff, it is especially useful when a sitemap is present, i.e, robots.txt:

```
nikto -h <IP>
```



