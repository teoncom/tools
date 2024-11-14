package aes

import "testing"

const secretKey = "IzmFwDpM0c3kBZvsTzwCu0el1lqwmvcy"
const originalText = "Hello World!"
const encryptedText = "ei3aVOPbQR2NOokWTrl4Qw=="

func TestAesEncrypt(t *testing.T) {
	ciphertext := Encrypt(originalText, secretKey)

	t.Log("result: " + ciphertext)

	if ciphertext == encryptedText {
		t.Log("TestAesEncrypt Pass")
	} else {
		t.Error("TestAesEncrypt Fail")
	}
}

func TestAesDecrypt(t *testing.T) {
	plaintext := Decrypt(encryptedText, secretKey)

	t.Log("result: " + plaintext)

	if plaintext == originalText {
		t.Log("TestAesDecrypt Pass")
	} else {
		t.Error("TestAesDecrypt Fail")
	}
}
