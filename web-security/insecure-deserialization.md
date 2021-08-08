# Insecure Deserialization

### JWT

### Edit JWT

We can use this website to modify a JWT token:

{% embed url="https://jwt.io/" %}

### Keys

If the JWT is encrypted with a signature but we can modify the signature then we may be able to generate our own private key with openssl:

```text
openssl genrsa -out privKey.key 2048
```

