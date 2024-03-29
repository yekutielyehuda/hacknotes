# Shell-Fu

## Process Control

List all processes:

```
ps -ef
```

Options:

* e: select all processes
* f: display full format listing (UID, PID, PPID, etc.)

Search for specific applications or commands:

```
ps -fC <application_name-or-command_name>
```

Then we can kill a process with:

```
kill <PID>
```

Alternatively, we can kill using the relative path of an application/program:

```bash
pkill ssh
```

## Files Size

Print human-readable size:

```
du -hs filename
```

## Archive/Compressed Files



### Compressing files

|                                                                          |                                                                                                                                                  |
| ------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Syntax**                                                               | **Example(s)**                                                                                                                                   |
| gzip {filename}                                                          | <p>gzip mydata.doc  <br>gzip *.jpg  <br>ls -l</p>                                                                                                |
| bzip2 {filename}                                                         | <p>bzip2 mydata.doc  <br>bzip2 *.jpg  <br>ls -l</p>                                                                                              |
| zip {.zip-filename} {filename-to-compress}                               | <p>zip mydata.zip mydata.doc  <br>zip data.zip *.doc  <br>ls -l</p>                                                                              |
| <p>tar -zcvf {.tgz-file} {files}  <br>tar -jcvf {.tbz2-file} {files}</p> | <p>tar -zcvf data.tgz <em>.doc</em>  <br><em>tar -zcvf pics.tar.gz</em> .jpg <em>.png</em>  <br><em>tar -jcvf data.tbz2</em> .doc  <br>ls -l</p> |

### Decompressing Files

| Name             | Summary                                        |
| ---------------- | ---------------------------------------------- |
| Unpack \*.tar    | `tar -xvf ./file.tar`                          |
| Unpack \*.tar.gz | `tar xvzf ./file.tar.gz`                       |
| Unpack \*.rar    | `unrar e ./file.rar`                           |
| Unpack \*.zip    | `unzip ./file.zip`                             |
| Unpack \*.gz     | `gunzip ./file.gz; gzip -d file.gz`            |
| Unpack \*.bz2    | `tar -jxvf file.tar.bz2 -C /tmp/extract_here/` |
| Unpack \*.7z     | `7z e ./file.7z` install p7zip first           |
| Unpack \*.xz     | `tar -xf ./file.tar.xz`                        |
| Unpack \*.jar    | `jar -xvf ./file.jar`                          |
| Unpack \*.war    | `jar -xvf ./file.war`                          |
| Unpack \*.tgz    | `tar -xf ./file.tgz`                           |

### List the contents of an archive/compressed file

Sometimes you just want to look at the files inside of an archive or a compressed file. Then all of the commands below support the file list option:

|                                                    |                                                                                                                                  |                                                        |
| -------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------ |
| Syntax                                             | Description                                                                                                                      | Example(s)                                             |
| gzip -l {.gz file}                                 | List files from a [GZIP](https://www.cyberciti.biz/howto/question/general/compress-file-unix-linux-cheat-sheet.php#gzip) archive | gzip -l mydata.doc.gz                                  |
| unzip -l {.zip file}                               | List files from a [ZIP](https://www.cyberciti.biz/howto/question/general/compress-file-unix-linux-cheat-sheet.php#zip) archive   | unzip -l mydata.zip                                    |
| <p>tar -ztvf {.tar.gz}   <br>tar -jtvf {.tbz2}</p> | List files from a [TAR](https://www.cyberciti.biz/howto/question/general/compress-file-unix-linux-cheat-sheet.php#tar) archive   | <p>tar -ztvf pics.tar.gz   <br>tar -jtvf data.tbz2</p> |

### unzip

Unzip a zip file with:

```
unzip archive.zip
```

### tar

Unzip tar.gz files with:

```
tar -xf archive.tar.gz
tar -xvf archive.tar.gz
```

&#x20;Use the `--directory` (`-C`) to extract archive files in a specific directory:

```
tar -xf archive.tar.gz -C /home/user/files
```

Extract specific files with:

```
tar -xf archive.tar.gz file1 file2
```

When extracting files, you must provide their exact names including the path, as printed by `--list` (`-t`).

Extracting one or more directories from an archive is the same as extracting files:

```
tar -xf archive.tar.gz dir1 dir2
```

Extract from STDIN:

```
wget -c https://somewhere/source/blender-2.80.tar.gz -O - | sudo tar -xz
```

List archive contents with:

```
tar -tf archive.tar.gz
```

### 7z

We can decompress some compressed files with 7z:

```
7z l compressed.tgz
7z x compressed.tgz
```

**Examine .zip**

```
7z l -slt Access Control.zip
```

**Examine .gz**

```
zcat filename.gz
```

## Virtual Files (VHD)

List the contents of a VHD file:

```
7z l filename.vhd
```

### guestmount

Mount a VHD file as read-only on your host:

```
guestmount -add filename.vhd --inspector -ro -v
```

## Checksums

We can perform checksums:

```
md5sum filename.txt
sh1sum filename.txt
sha256sum filename.txt
```

## Comparing Files

### comm

Compares two text files:

```
comm file1.txt file2.txt
com -12 file1.txt file2.txt
```

### diff

Detect differences between files

```
diff -c file_1.txt file_2.txt
diff -u file_1.txt file_2.txt
```

Flags:

* \-c = context format
* \-u = unified format

Symbols:

* \- appears in the first file but not in the second file
* \+ appears in the second file but not in the first file 

### vimdiff

vimdiff - opens each file, one in each windows.

The differences are highlighted.

```
vimdiff file1.txt file2.txt
```

Shortcuts:

* Ctrl+W LeftArrow = switch to the left window
* ] c = jump to the next change
* \[c = jump to the previous change
* d+o = get the change from the other window and put it in the current one
* d+p = get the change from the current window and put it in the other one

## Filtering

### find

find - search for files in a directory hierarchy

Find all the files whose name is `test.txt` in the current working directory

```
find . -name test.txt 2>/dev/null
```

Find all the files whose name is `test.txt` under /home directory

```
find /home -name test.txt 2>/dev/null
```

Find all the files whose name is `test.txt` with ignoring the case under /home directory

```
find /home -iname test.txt 2>/dev/null
```

Find directories whose name is `Test` in / directory

```
find / -type d -name Test 2>/dev/null
```

Find all `php` files in the current working directory

```
find . -type f -name "*.php" 2>/dev/null
```

Find files with `777` Permissions

```
find . type f -perm 777 2>/dev/null
```

Find files without `777` Permissions

```
find . type f ! -perm 777 2>/dev/null
```

Find all empty files under `/tmp`

```
find /tmp -type f -empty 2>/dev/null
```

File all hidden Files under `/tmp`

```
find /tmp -type f -name ".*" 2>/dev/null
```

Find all `test.txt` files under `/` owned by root

```
find / -name test.txt -user root 2>/dev/null
```

Find last 50 days modified files

```
find / -mtime 50 2>/dev/null
```

Find last 50 days accessed Files

```
find / -atime 50 2>/dev/null
```

Find last 50-100 days modified Files

```
find / -mtime +50 -mtime -100 2>/dev/null
```

Find changed files in the last 1 Hour

```
find / -cmin -60 2>/dev/null
```

Find modified files in the last 1 Hour

```
find / -mmin -60 2>/dev/null
```

Find 50MB files

```
find / -size 50M 2>/dev/null
```

Find multiple files with multiple filters:

```
find \-type -f 2>/dev/null | grep -v -E "themes|modules"
```

### awk

Gawk is the GNU Project's implementation of the AWK programming language. It conforms to the definition of the language in the POSIX 1003.1 Standard. This version in turn is based on the description in The AWK Programming Language, by Aho, Kernighan, and Weinberger, with the additional features found in the System V Release 4 version of UNIX awk. Gawk also provides more recent Bell Laboratories awk extensions and a number of GNU-specific extensions. This text was extracted from [here](https://linux.die.net/man/1/awk).

Print every line in a file

```bash
awk '{print}' test.txt
```

Print the lines which contain the given pattern.

```bash
awk '/test/ {print}' test.txt
```

Print the fields 1 and 4 with delimiter whitespace

```bash
awk '{print $1,$4}' test.txt
```

Display a block of the test starts with the word start and ends with the word end

```bash
awk '/start/,/stop/' file.txt
```

Print the last column:

```bash
awk 'NF{print $NF}'
```

Print the first column (space)

```bash
awk '{print $1}'
```

Print the first column using `:` as the field separator

```bash
awk -F ":"  '{print $1}'
```

Print multiple columns

```bash
awk -F ":"  '{print $1 $6 $8}'
```

Print multiple columns with tabs

```bash
awk -F ":"  '{print $1\t$6\t$8}'
```

Print the end of every line that starts with `/` forward slash

```bash
awk -F "/" '/^\// {print $NF}'
```

Print them with tabs 3 columns of a line that have `/dev` and `/loop`.

```bash
awk '/\/dev\/loop/' '{print $1"\t"$2"\t"$3}'
```

Print the lines that are greater than 7 characters.

```bash
awk 'length($0) > 7' input_file
```

Print every line where the last field ends with `/bin/bash`

```bash
awk '{if($NF == "/bin/bash") print $0}'
```

Print the entire line where the first character is either `a` or `b`.

```bash
awk '$1 ~ /^[a,b]/ {print 0}'
```

### cut

cut - remove sections from each line of files

> Print selected parts of lines from each FILE to standard output.

Displays 2nd character from each line of a file

```
cut -c2 test.txt
```

Display first 3 character of from each line of a file

```
cut -c1-3 test.txt
```

Display characters starting from 3rd character to the end of each line of a file

```
cut -c3- test.txt
```

Display first 8 characters of from each line of a file

```
cut -c-8 test.txt
```

Display 1st field when : is used as a delimeter

```
cut -d':' -f1 test.txt
```

Display 1st and 6th fields when : is used as a delimeter

```
cut -d':' -f1,6 test.txt
```

Display all fields except 7th field when : is used as a delimeter

```
cut -d':' –complement -s -f7 test.txt
```

### grep

**grep** searches the named input FILEs (or standard input if no files are named, or if a single hyphen-minus (**-**) is given as file name) for lines containing a match to the given PATTERN. By default, **grep** prints the matching lines.

In addition, two variant programs **egrep** and **fgrep** are available. **egrep** is the same as **grep -E**. **fgrep** is the same as **grep -F**. Direct invocation as either **egrep** or **fgrep** is deprecated, but is provided to allow historical applications that rely on them to run unmodified.

The text above was extracted from [here](https://linux.die.net/man/1/grep).

Search all lines with the specified string in a file

```
grep "string" test.txt
```

Search all lines with the specified string in a file pattern (test\_1.txt, test\_2.txt, test\_3.txt ...)

```
grep "string" test_*.txt
```

Case insensitive search all lines with the specified string in a file

```
grep -i "string" test.txt
```

Match regex in files (\*)

```
grep "REGEX" test.txt
```

Match lines with the pattern start with "first" and end with "last" with anything in-between

```
grep "start.*end" test.txt
```

Search for full words, not for sub-strings

```
grep -iw "is" test.txt
```

Display line matches the pattern and N lines after match

```
grep -A 3 "string" test.txt
```

Display line matches the pattern and N lines before the match

```
grep -B 2 "string" test.txt
```

Display line matches the pattern and N lines before match and N lines after match

```
grep -C 2 "string" test.txt
```

Search all files recursively

```
grep -r "string" *
```

Display all lines that don’t match the given pattern

```
grep -v "string" test.txt
```

Display lines that don’t match all the given pattern (if there are more than one pattern)

```
grep -v -e "string1" -v -e "string2" test.txt
```

Count the number of lines that matches the pattern

```
grep -c "string" test.txt
```

Count the number of lines that don’t match the pattern

```
grep -v -c "string" test.txt
```

Display only the filenames containing the given pattern (test\_1.txt, test\_2.txt, test\_3.txt ...)

```
grep -l "string" test_*.txt
```

Show only the matched string, not the whole line

```
grep -o "start.*end" test.txt
```

Show line number while Displaying the output

```
grep -n "string" test.txt
```

Multiple texts filtering, case insensitive, recursive on root (/) directory:

```
grep -r -i -E "text2|text1" /
```

Filter everything inside quotes:

```
grep -o 'cpassword="[^"]*"'
```

#### (\*) Regex:

```
? The preceding item is optional and matched at most once.
* The preceding item will be matched zero or more times.
+ The preceding item will be matched one or more times.
{n} The preceding item is matched exactly n times.
{n,} The preceding item is matched n or more times.
{,m} The preceding item is matched at most m times.
{n,m} The preceding item is matched at least n times, but not more than m times.
```

### head & tail

head: Print the first 10 lines of each FILE to standard output. With more than one FILE, precede each with a header giving the file name

tail: Print the last 10 lines of each FILE to standard output. With more than one FILE, precede each with a header giving the file name.

Display the first ten lines of test.txt

```
head test.txt
```

Display first 5 lines of test.txt

```
head -n5 test.txt
```

Display first 5 lines of test.txt (n is really necessary)

```
head -5 test.txt
```

Display the last ten lines of test.txt

```
tail test.txt
```

Display last 5 lines of test.txt

```
tail -n5 test.txt
```

Display last 5 lines of test.txt (n is really necessary)

```
tail -5 test.txt
```

### sed

&#x20;Sed is a stream editor. A stream editor is used to perform basic text transformations on an input stream (a file or input from a pipeline). While in some ways similar to an editor which permits scripted edits (such as ed), sed works by making only one pass over the **input**(s) and is consequently more efficient. But it is sed's ability to filter text in a pipeline that particularly distinguishes it from other types of editors. This text was extracted from [here](https://linux.die.net/man/1/sed).

Return lines 5 through 10 from test.txt

```
sed -n '5,10p' test.txt
```

Print the entire file except for lines 20 through 35 from test.txt

```
sed -n '20,35d' test.txt
```

Display lines 5-7 and 10-13 from test.txt

```
sed -n -e '5,7p' -e '10,13p' test.txt
```

Replace every instance of the word 'test' with 'real' in test.txt

```
sed 's/test/real/g' test.txt
```

Replace every instance of the word 'test' with 'real' in test.txt by ignoring character case

```
sed 's/test/real/gi' test.txt
```

Replace multiple spaces with a single space

```
sed 's/ */ /g' test.txt
```

Replace every instance of the word 'test' with 'real' within lines 30-40 in test.txt

```
sed '30,40 s/test/real/g' test.txt
```

Delete lines that start with or empty lines (\*\*)

```
sed '/^\|^$\| */d' test.txt
```

Replace words zip and Zip with rar in file test.txt

```
sed 's/[Zz]ip/rar/g' test.txt
```

Insert one blank line between each line

```
sed G test.txt
```

Remove the hidden new lines (DOS newline chars) at the end of each line (and do the changes in file)

```
sed -i 's/\r//' test.txt
```

One line

```
sed 's/find/ replace'
sed 's/find/replace' < file_as_input > sed-output
```

Global

```
sed 's/find/replace'/g < file_as_input > sed-output
```

Replace the contents of a file

```
sed -i 's/find/replace'/g file_as_input
```

Replace multiple strings

```
cat file_as_input | sed -e 's|find|replace|g' -e 's#bin#b#g'
```

Delete spaces

```
sed -i 's/ *$//' file_as_input
```

Delete extra tabs

```
sed -i 's/[[:space:]]$//' file_as_input
```

Uppercase

```
sed 's/[a-z]/\U&/g' file_as_input
```

Lowercase

```
sed 's/[A-Z]/\L&/g' file_as_input
```

Regex can be explained as below:

```
^ menas line start with 
\| means or
^$ means blank line
And  * means lines start with some space and then
```

### sort

sort - sort lines of text files

Show the sorted version of the file

```
sort test.txt
```

Show the sorted version of the file in the reverse order

```
sort -r test.txt
```

Show the sorted version of the file according to the 2nd column (n is used if the column contains numerical values)

```
sort -nk2 test.txt
```

Show the sorted version of the file according to the 3rd column (no numerical value in column 3)

```
sort -k3 test.txt
```

Use sort command with a pipeline (without any file)

```
ls -lah | sort -nk2
```

Sort the lines and remove duplicates (again this is just showing, not changing any content)

```
sort -u test.txt
```

Sort the contents of 2 files and concatenate the output

```
sort file1.txt file2.txt
```

Sort the contents of 2 files and concatenate the output, then remove the duplicates

```
sort -u file1.txt file2.txt
```

### uniq

uniq - report or omit repeated lines

Show unique lines only (without showing duplicate lines)

```
uniq test.txt
```

Show unique lines with line numbers

```
uniq -c test.txt
```

Show repeated lines only

```
uniq -d test.txt
```

Show repeated lines (with all repetitions)

```
uniq -D test.txt
```

Show the lines that never repeat

```
uniq -u test.txt
```

Show unique lines case-insensitive

```
uniq -i test.txt
```

## References

{% embed url="https://github.com/areyou1or0/Bash-Fu" %}



