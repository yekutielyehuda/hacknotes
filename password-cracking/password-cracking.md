# Password Cracking

## John

A simple way to crack password hashes with a dictionary attack:

```text
john --wordlist=/usr/share/wordlists/rockyou.txt passwords.txt
```

### Converting Formats for John

```text
find / -name '*2john' 2>/dev/null
```

This GitHub repo has more converters:

{% embed url="https://github.com/openwall/john/tree/bleeding-jumbo/run" %}

## Misc

### Crack an OpenSSL Password

Bruteforce an OpenSSL encrypted file:

```bash
#!/bin/bash

function ctrl_c(){
    echo -e "\n[!] Exiting...\n"
    exit 1
}

#Ctrl+C
trap ctrl_c INT

# Iterate over each line in passwords.txt
for password in $(cat passwords.txt); do
    # AES-256-CBC is the most common cipher in OpenSSL, you may change it...
    openssl aes-256-cvc -d -in filename.crypted -out filename.txt -k $password 2>/dev/null
    # If successful then print the password, hence the reason for the status code "0".
    if [ "$(echo $?)" == "0" ]; then
        echo -e "\n[+] The password is: $password\n"
        exit 0
    fi
done
```

 
