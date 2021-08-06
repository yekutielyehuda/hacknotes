# OpenSSL

## Open SSL Information

OpenSSL is a cryptography toolkit implementing the Secure Sockets Layer \( SSL v2/v3\) and Transport Layer Security \( TLS v1\) network protocols and related cryptography standards required by them.

The **openssl** program is a command-line tool for using the various cryptography functions of OpenSSL's **crypto** library from the shell. It can be used for

```text
o  Creation and management of private keys, public keys and parameters
o  Public key cryptographic operations
o  Creation of X.509 certificates, CSRs and CRLs
o  Calculation of Message Digests
o  Encryption and Decryption with Ciphers
o  SSL/TLS Client and Server Tests
o  Handling of S/MIME signed or encrypted mail
o  Time Stamp requests, generation and verification
```

Reference:

{% embed url="https://linux.die.net/man/1/openssl" %}

### Private Keys

We can generate a private key as follows:

```text
openssl genrsa -out priv.key 2048
```

## Certificates



