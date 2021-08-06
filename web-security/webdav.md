# WebDAV

## WebDAV

WebDAV stands for "Web-based Distributed Authoring and Versioning". It is a set of extensions to the HTTP protocol which allows users to collaboratively edit and manage files on remote web servers.

**WebDAV** \(**Web Distributed Authoring and Versioning**\) is an extension of the [Hypertext Transfer Protocol](https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol) \(HTTP\) that allows [clients](https://en.wikipedia.org/wiki/Web_client) to perform remote [Web](https://en.wikipedia.org/wiki/World_Wide_Web) content authoring operations. WebDAV is defined in [RFC](https://en.wikipedia.org/wiki/RFC_%28identifier%29) [4918](https://datatracker.ietf.org/doc/html/rfc4918) by a [working group](https://en.wikipedia.org/wiki/Working_group) of the [Internet Engineering Task Force](https://en.wikipedia.org/wiki/Internet_Engineering_Task_Force) \(IETF\).

The WebDAV protocol provides a framework for users to create, change and move documents on a [server](https://en.wikipedia.org/wiki/Server_%28computing%29). The most important features of the WebDAV protocol include the maintenance of properties about an author or modification date, [namespace](https://en.wikipedia.org/wiki/Namespace) management, collections, and overwrite protection. Maintenance of properties includes such things as the creation, removal, and querying of file information. Namespace management deals with the ability to copy and move web pages within a server's namespace. Collections deal with the creation, removal, and listing of various resources. Lastly, overwrite protection handles aspects related to the locking of files.

The text above was extracted from [Wikipedia](https://en.wikipedia.org/wiki/WebDAV).

## Enumeration

### cadaver

 cadaver is a command-line [WebDAV](http://www.webdav.org/) client for Unix. It supports file upload, download, on-screen display, namespace operations \(move/copy\), collection creation and deletion, and locking operations. This text was extracted from [here](http://www.webdav.org/cadaver/).

```text
cadaver http://$ip
```

### davtest

{% embed url="https://github.com/cldrn/davtest" %}

DAVTest tests WebDAV-enabled servers by uploading test executable files, and then \(optionally\) uploading files that allow for command execution or other actions directly on the target. It is meant for penetration testers to quickly and easily determine if enabled DAV services are exploitable.

DAVTest supports:

* Automatically send exploit files
* Automatic randomization of the directory to help hide files
* Send text files and try MOVE to the executable name
* Basic and Digest authorization
* Automatic clean-up of uploaded files
* Send an arbitrary file

```text
davtest -url http://10.10.10.10
```

