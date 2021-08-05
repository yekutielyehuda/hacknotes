# Shell-Fu

## Filtering

### find

find - search for files in a directory hierarchy

Find all the files whose name is test.txt in the current working directory

```text
find . -name test.txt 2>/dev/null
```

Find all the files whose name is test.txt under /home directory

```text
find /home -name test.txt 2>/dev/null
```

Find all the files whose name is test.txt with ignoring the case under /home directory

```text
find /home -iname test.txt 2>/dev/null
```

Find directories whose name is Test in / directory

```text
find / -type d -name Test 2>/dev/null
```

Find all php files in the current working directory

```text
find . -type f -name "*.php" 2>/dev/null
```

Find Files With 777 Permissions

```text
find . type f -perm 777 2>/dev/null
```

Find Files Without 777 Permissions

```text
find . type f ! -perm 777 2>/dev/null
```

Find all empty files under /tmp

```text
find /tmp -type f -empty 2>/dev/null
```

File all Hidden Files under /tmp

```text
find /tmp -type f -name ".*" 2>/dev/null
```

Find all test.txt files under / owned by root

```text
find / -name test.txt -user root 2>/dev/null
```

Find last 50 days modified files

```text
find / -mtime 50 2>/dev/null
```

Find Last 50 Days Accessed Files

```text
find / -atime 50 2>/dev/null
```

Find Last 50-100 Days Modified Files

```text
find / -mtime +50 -mtime -100 2>/dev/null
```

Find Changed Files in Last 1 Hour

```text
find / -cmin -60 2>/dev/null
```

Find Modified Files in Last 1 Hour

```text
find / -mmin -60 2>/dev/null
```

Find 50MB Files

```text
find / -size 50M 2>/dev/null
```

### awk

Gawk is the GNU Project's implementation of the AWK programming language. It conforms to the definition of the language in the POSIX 1003.1 Standard. This version in turn is based on the description in The AWK Programming Language, by Aho, Kernighan, and Weinberger, with the additional features found in the System V Release 4 version of UNIX awk. Gawk also provides more recent Bell Laboratories awk extensions and a number of GNU-specific extensions. This text was extracted from [here](https://linux.die.net/man/1/awk).

Print every line in a file

```text
awk '{print}' test.txt
```

Print the lines which contain the given pattern.

```text
awk '/test/ {print}' test.txt
```

Print the fields 1 and 4 with delimeter whitespace

```text
awk '{print $1,$4}' test.txt
```

Display a block of the test starts with the word start and ends with the word end

```text
awk '/start/,/stop/' file.txt
```

### cut

cut - remove sections from each line of files

> Print selected parts of lines from each FILE to standard output.

Displays 2nd character from each line of a file

```text
cut -c2 test.txt
```

Display first 3 character of from each line of a file

```text
cut -c1-3 test.txt
```

Display characters starting from 3rd character to the end of each line of a file

```text
cut -c3- test.txt
```

Display first 8 characters of from each line of a file

```text
cut -c-8 test.txt
```

Display 1st field when : is used as a delimeter

```text
cut -d':' -f1 test.txt
```

Display 1st and 6th fields when : is used as a delimeter

```text
cut -d':' -f1,6 test.txt
```

Display all fields except 7th field when : is used as a delimeter

```text
cut -d':' –complement -s -f7 test.txt
```

### grep

**grep** searches the named input FILEs \(or standard input if no files are named, or if a single hyphen-minus \(**-**\) is given as file name\) for lines containing a match to the given PATTERN. By default, **grep** prints the matching lines.

In addition, two variant programs **egrep** and **fgrep** are available. **egrep** is the same as **grep -E**. **fgrep** is the same as **grep -F**. Direct invocation as either **egrep** or **fgrep** is deprecated, but is provided to allow historical applications that rely on them to run unmodified.

The text above was extracted from [here](https://linux.die.net/man/1/grep).

Search all lines with the specified string in a file

```text
grep "string" test.txt
```

Search all lines with the specified string in a file pattern \(test\_1.txt, test\_2.txt, test\_3.txt ...\)

```text
grep "string" test_*.txt
```

Case insensitive search all lines with the specified string in a file

```text
grep -i "string" test.txt
```

Match regex in files \(\*\)

```text
grep "REGEX" test.txt
```

Match lines with the pattern start with "first" and end with "last" with anything in-between

```text
grep "start.*end" test.txt
```

Search for full words, not for sub-strings

```text
grep -iw "is" test.txt
```

Display line matches the pattern and N lines after match

```text
grep -A 3 "string" test.txt
```

Display line matches the pattern and N lines before the match

```text
grep -B 2 "string" test.txt
```

Display line matches the pattern and N lines before match and N lines after match

```text
grep -C 2 "string" test.txt
```

Search all files recursively

```text
grep -r "string" *
```

Display all lines that don’t match the given pattern

```text
grep -v "string" test.txt
```

Display lines that don’t match all the given pattern \(if there are more than one pattern\)

```text
grep -v -e "string1" -v -e "string2" test.txt
```

Count the number of lines that matches the pattern

```text
grep -c "string" test.txt
```

Count the number of lines that don’t match the pattern

```text
grep -v -c "string" test.txt
```

Display only the filenames containing the given pattern \(test\_1.txt, test\_2.txt, test\_3.txt ...\)

```text
grep -l "string" test_*.txt
```

Show only the matched string, not the whole line

```text
grep -o "start.*end" test.txt
```

Show line number while Displaying the output

```text
grep -n "string" test.txt
```

Multiple texts filtering, case insensitive, recursive on root \(/\) directory:

```text
grep -r -i -E "text2|text1" /
```

#### \(\*\) Regex:

```text
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

```text
head test.txt
```

Display first 5 lines of test.txt

```text
head -n5 test.txt
```

Display first 5 lines of test.txt \(n is really necessary\)

```text
head -5 test.txt
```

Display the last ten lines of test.txt

```text
tail test.txt
```

Display last 5 lines of test.txt

```text
tail -n5 test.txt
```

Display last 5 lines of test.txt \(n is really necessary\)

```text
tail -5 test.txt
```

### sed

 Sed is a stream editor. A stream editor is used to perform basic text transformations on an input stream \(a file or input from a pipeline\). While in some ways similar to an editor which permits scripted edits \(such as ed\), sed works by making only one pass over the **input**\(s\) and is consequently more efficient. But it is sed's ability to filter text in a pipeline that particularly distinguishes it from other types of editors. This text was extracted from [here](https://linux.die.net/man/1/sed).

Return lines 5 through 10 from test.txt

```text
sed -n '5,10p' test.txt
```

Print the entire file except for lines 20 through 35 from test.txt

```text
sed -n '20,35d' test.txt
```

Display lines 5-7 and 10-13 from test.txt

```text
sed -n -e '5,7p' -e '10,13p' test.txt
```

Replace every instance of the word 'test' with 'real' in test.txt

```text
sed 's/test/real/g' test.txt
```

Replace every instance of the word 'test' with 'real' in test.txt by ignoring character case

```text
sed 's/test/real/gi' test.txt
```

Replace multiple spaces with a single space

```text
sed 's/ */ /g' test.txt
```

Replace every instance of the word 'test' with 'real' within lines 30-40 in test.txt

```text
sed '30,40 s/test/real/g' test.txt
```

Delete lines that start with or empty lines \(\*\*\)

```text
sed '/^\|^$\| */d' test.txt
```

Replace words zip and Zip with rar in file test.txt

```text
sed 's/[Zz]ip/rar/g' test.txt
```

Insert one blank line between each line

```text
sed G test.txt
```

Remove the hidden new lines \(DOS newline chars\) at the end of each line \(and do the changes in file\)

```text
sed -i 's/\r//' test.txt
```

Regex can be explained as below:

```text
^ menas line start with 
\| means or
^$ means blank line
And  * means lines start with some space and then
```

### sort

sort - sort lines of text files

Show the sorted version of the file

```text
sort test.txt
```

Show the sorted version of the file in the reverse order

```text
sort -r test.txt
```

Show the sorted version of the file according to the 2nd column \(n is used if the column contains numerical values\)

```text
sort -nk2 test.txt
```

Show the sorted version of the file according to the 3rd column \(no numerical value in column 3\)

```text
sort -k3 test.txt
```

Use sort command with a pipeline \(without any file\)

```text
ls -lah | sort -nk2
```

Sort the lines and remove duplicates \(again this is just showing, not changing any content\)

```text
sort -u test.txt
```

Sort the contents of 2 files and concatenate the output

```text
sort file1.txt file2.txt
```

Sort the contents of 2 files and concatenate the output, then remove the duplicates

```text
sort -u file1.txt file2.txt
```

### uniq

uniq - report or omit repeated lines

Show unique lines only \(without showing duplicate lines\)

```text
uniq test.txt
```

Show unique lines with line numbers

```text
uniq -c test.txt
```

Show repeated lines only

```text
uniq -d test.txt
```

Show repeated lines \(with all repetitions\)

```text
uniq -D test.txt
```

Show the lines that never repeat

```text
uniq -u test.txt
```

Show unique lines case-insensitive

```text
uniq -i test.txt
```



