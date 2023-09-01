package service

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
)

func Sign(private *ecdsa.PrivateKey, message string) (string, error) {
	messageBytes, err := hex.DecodeString(message)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(messageBytes)
	signature, err := ecdsa.SignASN1(rand.Reader, private, hash[:])
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(signature), nil
}

func Verify(public *ecdsa.PublicKey, message, signature string) bool {
	signatureBytes, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}
	messageBytes, err := hex.DecodeString(message)
	if err != nil {
		return false
	}
	hash := sha256.Sum256(messageBytes)
	return ecdsa.VerifyASN1(public, hash[:], signatureBytes)
}
