# OpenSSL

## Open SSL Information

OpenSSL is a robust, commercial-grade, and full-featured toolkit for the Transport Layer Security \(TLS\) and Secure Sockets Layer \(SSL\) protocols. It is also a general-purpose cryptography library. For more information about the team and community around the project, or to start making your own contributions, start with the [community](https://www.openssl.org/community) page. To get the latest news, download the source, and so on, please see the sidebar or the buttons at the top of every page.

OpenSSL is licensed under an Apache-style license, which basically means that you are free to get and use it for commercial and non-commercial purposes subject to some simple license conditions.

The text above was extracted from here:

{% embed url="https://www.openssl.org/" %}

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



