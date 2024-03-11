package service

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"

	"github.com/sinohope/mpc-node-callback-demo/service/ecies"
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

func PEM2PrivateKey(pemData []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing the private key")
	}

	priKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		keyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %v", err)
		}
		priKey, ok := keyInterface.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not an ECDSA private key")
		}
		return priKey, nil
	}
	return priKey, nil
}

// Decrypt decrypts an ECIES ciphertext.
func Decrypt(pri *ecdsa.PrivateKey, cipherText string) (string, error) {
	private := ecies.ImportECDSA(pri)

	ct, err := hex.DecodeString(cipherText)
	if err != nil {
		return "", fmt.Errorf("decode cipher text failed, %v", err)
	}
	m, err := private.Decrypt(ct, nil, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt failed, %v", err)
	}
	return hex.EncodeToString(m), nil
}
