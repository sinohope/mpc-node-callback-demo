package ecies

import (
	"crypto/rand"
	"errors"
	"fmt"
	mrand "math/rand"
	"testing"
	"time"
)

const (
	characterBytes  = "!@#$%^&*?"
	digitBytes      = "1234567890"
	highLetterBytes = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lowLetterBytes  = "abcdefghijklmnopqrstuvwxyz"
)

func TestGenSalt(t *testing.T) {
	t.SkipNow()
	salt := make([]byte, 32)
	rand.Read(salt)
	fmt.Printf("%x\n", salt)
}

func TestDeriveKeyPairAccordingPasswords(t *testing.T) {
	for i := 0; i < 10; i++ {
		for j := 0; j < 10; j++ {
			pwd, _ := simpleNewPwd(12 + i)
			sk1, err1 := DeriveKeyPairAccordingPasswords(pwd)
			sk2, err2 := DeriveKeyPairAccordingPasswords(pwd)
			if err1 != nil || err2 != nil {
				t.Errorf("pwd: %s, err1: %v, err2: %v\n", pwd, err1, err2)
			}
			if sk1.D.Cmp(sk2.D) != 0 {
				t.Errorf("same pwd got different private key, pwd: %s, sk1: %x, sk2: %x\n", pwd, sk1.D.Bytes(), sk2.D.Bytes())
			}
		}
	}
}

func BenchmarkDeriveKeyPairAccordingPasswords(b *testing.B) {
	pwd, _ := simpleNewPwd(15)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := DeriveKeyPairAccordingPasswords(pwd); err != nil {
			b.Fatal(err)
		}
	}
}

// SimpleNewPwd 复杂密码生成 简易实现方式
func simpleNewPwd(length int) (pwd string, err error) {
	// check length
	if length < 4 || length > 25 {
		return "", errors.New("length is invalid")
	}
	// assign elements from 4 kinds of base elements
	r := mrand.New(mrand.NewSource(time.Now().Unix()))
	factor := length / 4
	characters := []rune(characterBytes)
	digits := []rune(digitBytes)
	highLetters := []rune(highLetterBytes)
	lowerLetters := []rune(lowLetterBytes)
	// get rand elements
	b := make([]rune, length)
	for i := range b[:factor] {
		b[i] = highLetters[r.Intn(len(highLetters))]
	}
	for i := range b[factor : factor*2] {
		b[i+factor] = lowerLetters[r.Intn(len(lowerLetters))]
	}
	for i := range b[factor*2 : factor*3] {
		b[i+factor*2] = characters[r.Intn(len(characters))]
	}
	for i := range b[factor*3:] {
		b[i+factor*3] = digits[r.Intn(len(digits))]
	}
	// shuffle
	mrand.Shuffle(len(b), func(i, j int) {
		i = r.Intn(length)
		b[i], b[j] = b[j], b[i]
	})
	return string(b), nil
}
