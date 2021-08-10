# XPATH Injection

## XML Information

XML \(Extensible Markup Language\) v1.0 is a markup language \(similar to HTML\) that is primarily used to describe data rather than to display it. XML documents are frequently utilized as databases due to their nature. Queries can read and write data, and the XML database looks exactly like an XML document.

XML Declaration, the XML declaration defines the current version number \(1.0 in our case\) and the encoding type:

```markup
<?xml version="1.0" encoding="ISO-8859-1"?>
```

Although it is not required, if it exists, it must be the first line in the document.

In contrast to HTML, you can use any naming convention you wish for elements, just as long as you follow these simple naming rules:

* Names must start with a letter or underscore and cannot start with the letters xml 
* Names are case sensitive 
* Names can contain letters, digits, periods but no spaces

## XPATH Information

XPath \(XML Path Language\) is a standard language used to query and navigate XML documents. At the time of this writing, the latest version is 3.0. XPath makes use of path expressions to select nodes from an XML document.

### XPATH Vulnerable Code

An example of an XPath query to look for a node user based on the inserted credentials can be this:

```markup
//user[username/text()='<USERNAME>' and password/text()='<PASSWORD>']
```

Where USERNMAE&gt; and PASSWORD&gt; are user-supplied input values, they should be sanitized before use.





