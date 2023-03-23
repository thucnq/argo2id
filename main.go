package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"strings"

	"golang.org/x/crypto/argon2"
)

const PARALLELISM = 1
const ITERATIONS = 2
const MEMORY_SIZE = 15 * 1024
const HASH_LENGTH = 32
const SALT_LENGTH = 8
const OUTPUT_TYPE = "encoded"
const PREFIX_PWD = "$argon2id$v=19$m=15360,t=2,p=1$"
const SALT = "b1SJf3"

var (
	ErrInvalidHash         = errors.New("the encoded hash is not in the correct format")
	ErrIncompatibleVersion = errors.New("incompatible version of argon2")
)

type params struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

func main() {
	inputPassword := "20cd8a2ec2243962f5c521ee8be5dcb3f6ab2ad1cd5aab39f19984d6bbe78021"
	encryptedPassword := "VkI4WWhDSlk$iLn909ydSF5uImvJsIl4x+Jz4U02AvOzrkp4Y5punVQ"
	// salt := "b1SJf3"

	p := &params{
		memory:      MEMORY_SIZE,
		iterations:  ITERATIONS,
		parallelism: PARALLELISM,
		saltLength:  SALT_LENGTH,
		keyLength:   HASH_LENGTH,
	}

	encryptedPassword = fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s", argon2.Version, p.memory, p.iterations, p.parallelism, encryptedPassword)
	fmt.Println(encryptedPassword)
	encodedHash, err := generateFromPassword(inputPassword, p)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(encodedHash)
	// match, err := comparePasswordAndHash(inputPassword, encodedHash)
	match, err := comparePasswordAndHash(inputPassword, encryptedPassword)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Match: %v\n", match)

	return
}

func comparePasswordAndHash(password, encodedHash string) (match bool, err error) {
	// Extract the parameters, salt and derived key from the encoded password
	// hash.
	p, salt, hash, err := decodeHash(encodedHash)
	if err != nil {
		return false, err
	}

	// Derive the key from the other password using the same parameters.
	otherHash := argon2.IDKey([]byte(password), salt, p.iterations, p.memory, p.parallelism, p.keyLength)

	// Check that the contents of the hashed passwords are identical. Note
	// that we are using the subtle.ConstantTimeCompare() function for this
	// to help prevent timing attacks.
	if subtle.ConstantTimeCompare(hash, otherHash) == 1 {
		return true, nil
	}
	return false, nil
}

func decodeHash(encodedHash string) (p *params, salt, hash []byte, err error) {
	vals := strings.Split(encodedHash, "$")
	if len(vals) != 6 {
		return nil, nil, nil, ErrInvalidHash
	}

	var version int
	_, err = fmt.Sscanf(vals[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, err
	}
	if version != argon2.Version {
		return nil, nil, nil, ErrIncompatibleVersion
	}

	p = &params{}
	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &p.memory, &p.iterations, &p.parallelism)
	if err != nil {
		return nil, nil, nil, err
	}

	salt, err = base64.RawStdEncoding.Strict().DecodeString(vals[4])
	if err != nil {
		return nil, nil, nil, err
	}
	p.saltLength = uint32(len(salt))

	hash, err = base64.RawStdEncoding.Strict().DecodeString(vals[5])
	if err != nil {
		return nil, nil, nil, err
	}
	p.keyLength = uint32(len(hash))

	return p, salt, hash, nil
}

func generateFromPassword(password string, p *params) (encodedHash string, err error) {
	salt, err := generateRandomBytes(p.saltLength)
	if err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, p.iterations, p.memory, p.parallelism, p.keyLength)

	// Base64 encode the salt and hashed password.
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	// Return a string using the standard encoded hash representation.
	encodedHash = fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.memory, p.iterations, p.parallelism, b64Salt, b64Hash)

	return encodedHash, nil
}

func generateRandomBytes(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}
