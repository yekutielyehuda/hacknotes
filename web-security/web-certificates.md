# Web Certificates

## Web Certificates

A website security certificate is essentially a digital stamp of approval from a certificate authority, which is an industry-trusted third party \(CA\). It's a digital file comprising information issued by a CA that certifies that a website is secure when accessed through an encrypted connection.

### Self-Signed Certificates

Self-Signed certificates may be dangerous but as long as you know from who and which data is in the certificate then you may trust it.

### OpenSSL

We can enumerate the certificate of a remote server with:

```text
openssl s_client -connect <IP:PORT>
```

