package service

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

func loadTSSNodePublicKey(path string) (*ecdsa.PublicKey, error) {
	pemData, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read the PEM file: %v", err)
	}
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing the public key")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}
	pubKey, ok := pubInterface.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA public key")
	}
	return pubKey, nil
}

func loadKeypair(path string) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	load := func(path string) (interface{}, error) {
		pemData, err := ioutil.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read the PEM file: %v", err)
		}
		var block *pem.Block
		for {
			block, pemData = pem.Decode(pemData)
			if block == nil {
				return nil, fmt.Errorf("failed to find PEM block containing the EC private key")
			}
			if block.Type == "EC PRIVATE KEY" {
				break
			}
		}
		keyInterface, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %v", err)
		}
		return keyInterface, nil
	}

	var err error
	var ok bool
	var privateKey *ecdsa.PrivateKey
	var result interface{}
	if result, err = load(path); err != nil {
		return nil, nil, fmt.Errorf("failed to load private key: %v", err)
	}
	if privateKey, ok = result.(*ecdsa.PrivateKey); !ok {
		return nil, nil, fmt.Errorf("private key is not an ECDSA private key")
	}
	return privateKey, &privateKey.PublicKey, nil
}
