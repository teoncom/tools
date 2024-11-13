package ecc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
)

// Key holds both private and public keys
type Key struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
}

// EncryptedMessage contains all components needed for decryption
type EncryptedMessage struct {
	EphemeralPublicKey []byte
	EncryptedData      []byte
	Nonce              []byte
	MAC                []byte
}

// GenerateKey generates a new ECC key pair
func GenerateKey() (*Key, error) {
	// Use P-256 curve (also known as secp256r1)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECC key: %v", err)
	}

	return &Key{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}, nil
}

// ExportPrivateKeyToPEM exports private key to PEM format
func ExportPrivateKeyToPEM(key *ecdsa.PrivateKey) (string, error) {
	// Convert private key to DER format
	derBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("failed to marshal private key: %v", err)
	}

	// Create PEM block
	block := pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: derBytes,
	}

	return string(pem.EncodeToMemory(&block)), nil
}

// ExportPublicKeyToPEM exports public key to PEM format
func ExportPublicKeyToPEM(key *ecdsa.PublicKey) (string, error) {
	// Convert public key to DER format
	derBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %v", err)
	}

	// Create PEM block
	block := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}

	return string(pem.EncodeToMemory(&block)), nil
}

// ImportPrivateKeyFromPEM imports private key from PEM format
func ImportPrivateKeyFromPEM(pemStr string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	return privateKey, nil
}

// ImportPublicKeyFromPEM imports public key from PEM format
func ImportPublicKeyFromPEM(pemStr string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}

	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA public key")
	}

	return ecdsaPub, nil
}

// Encrypt encrypts a message using ECIES-like hybrid encryption
func Encrypt(publicKey *ecdsa.PublicKey, message []byte) (*EncryptedMessage, error) {
	// Generate ephemeral key pair
	ephemeralKey, err := ecdsa.GenerateKey(publicKey.Curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %v", err)
	}

	// Perform ECDH to generate shared secret
	x, _ := publicKey.Curve.ScalarMult(publicKey.X, publicKey.Y, ephemeralKey.D.Bytes())
	sharedSecret := sha256.Sum256(x.Bytes())

	// Create AES cipher
	block, err := aes.NewCipher(sharedSecret[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	// Encrypt message
	ciphertext := gcm.Seal(nil, nonce, message, nil)

	// Marshal ephemeral public key
	ephemeralPublicKeyBytes := elliptic.Marshal(publicKey.Curve, ephemeralKey.PublicKey.X, ephemeralKey.PublicKey.Y)

	// Calculate MAC
	mac := sha256.Sum256(append(ephemeralPublicKeyBytes, ciphertext...))

	return &EncryptedMessage{
		EphemeralPublicKey: ephemeralPublicKeyBytes,
		EncryptedData:      ciphertext,
		Nonce:              nonce,
		MAC:                mac[:],
	}, nil
}

// Decrypt decrypts a message using ECIES-like hybrid encryption
func Decrypt(privateKey *ecdsa.PrivateKey, em *EncryptedMessage) ([]byte, error) {
	// Unmarshal ephemeral public key
	x, y := elliptic.Unmarshal(privateKey.Curve, em.EphemeralPublicKey)
	if x == nil {
		return nil, fmt.Errorf("failed to unmarshal ephemeral public key")
	}

	// Verify MAC
	mac := sha256.Sum256(append(em.EphemeralPublicKey, em.EncryptedData...))
	if !(hex.EncodeToString(mac[:]) == hex.EncodeToString(em.MAC)) {
		return nil, fmt.Errorf("MAC verification failed")
	}

	// Perform ECDH to recover shared secret
	sx, _ := privateKey.Curve.ScalarMult(x, y, privateKey.D.Bytes())
	sharedSecret := sha256.Sum256(sx.Bytes())

	// Create AES cipher
	block, err := aes.NewCipher(sharedSecret[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	// Decrypt message
	plaintext, err := gcm.Open(nil, em.Nonce, em.EncryptedData, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt message: %v", err)
	}

	return plaintext, nil
}
