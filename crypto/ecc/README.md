# ECC (Elliptic Curve Cryptography)

## Key features of this implementation:

### Key Generation:

* Uses P-256 curve (NIST curve, widely supported)
* Generates secure random keys
* Supports key export/import in PEM format

### Encryption:

* Uses hybrid encryption (ECIES-like scheme)
* Combines ECC with AES-GCM
* Includes MAC for authentication
* Supports messages of any size

### Key Management:

* PEM format support for easy sharing
* Separate public/private key handling
* Secure key serialization

## Advantages of ECC over RSA:

* Smaller key sizes (256-bit ECC ≈ 3072-bit RSA)
* Faster key generation
* Lower CPU usage
* Less memory required
* Smaller encrypted messages

## To use this in your application:

Generate keys:

```go
eccKey, err := GenerateKey()
```

Export public key to share:

```go
publicPEM, err := ExportPublicKeyToPEM(eccKey.PublicKey)
```

Encrypt message:

```go
encrypted, err := Encrypt(publicKey, []byte("Your message"))
```

Decrypt message:

```go
decrypted, err := Decrypt(privateKey, encrypted)
```

## Important security considerations:

1. Keep private keys secure
2. Use secure random number generation
3. Implement proper key management
4. Verify MACs before decryption
5. Use appropriate curves (P-256 is recommended)