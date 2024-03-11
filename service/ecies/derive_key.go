package ecies

import (
	"encoding/hex"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
)

const (
	argon2_derive_salt_hex = "e5e4a112164621b7dd73422972ddb518756d0a2a41994b7c3a18935876b2608b"
	argon2_time            = 1
	argon2_memory          = 128 * 1024 // 128MB
	argon2_threads         = 2
	min_len                = 12
	ecdsa_key_len          = 32
)

var (
	argon2_derive_salt, _ = hex.DecodeString(argon2_derive_salt_hex)
)

// DeriveKeyPairAccordingPasswords derive a keypair by an user inputed password
func DeriveKeyPairAccordingPasswords(password string) (prv *PrivateKey, err error) {
	if len(password) < min_len {
		return nil, errors.New("need a strong password, at least 12 characters")
	}
	return GenerateKey(newDeriveReader([]byte(password)), DefaultCurve, nil)
}

// deriveReader implements io.Reader for deriving key,
// the source is original from a user specific password, and derived by argon2id.
type deriveReader struct {
	source     []byte
	lastSource []byte
	readed     int
}

func newDeriveReader(password []byte) io.Reader {
	rawBytes := argon2.IDKey(password, argon2_derive_salt, argon2_time, argon2_memory, argon2_threads, ecdsa_key_len)
	lastSource := make([]byte, ecdsa_key_len)
	copy(lastSource, rawBytes)
	return &deriveReader{
		source:     rawBytes,
		lastSource: lastSource,
		readed:     0,
	}
}

func (r *deriveReader) Read(p []byte) (n int, err error) {
	if len(p) > len(r.source[r.readed:]) {
		// if the previous value is not a valid private key of the given curve,
		// then we continue to generates more data using the argon2id, with the `lastSource` as new password.
		rawBytes := argon2.IDKey(r.lastSource, argon2_derive_salt, argon2_time, argon2_memory, argon2_threads, ecdsa_key_len)
		r.lastSource = rawBytes
		r.source = append(r.source, rawBytes...)
	}
	n = copy(p, r.source[r.readed:])
	r.readed += n
	return
}
