// Package pwhash is a simple to use password hashing library. The defaults are
// set to be good for most purposes and it is backwards compatible with older
// password hashing schemes.
package pwhash

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"hash"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

// Hash returns a hashed version of the given password. Use this when the user
// enters a new password and store it as an opaque string in a database.
//
// You don't need to salt or do this operation multiple times, this is all
// handled for you.
func Hash(password string) string {
	salt := make([]byte, 12)
	_, err := rand.Read(salt)
	if err != nil {
		panic("unexpected: crypto/rand.Read returned an error: " + err.Error())
	}
	key := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	return "$argon2id$v=19$m=65536,t=1,p=4$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(key)
}

// Verify check whether a given password matches the hash. Use it for example
// this way:
//
//     hash := loadUser(username).hash
//     if !pwhash.Verify(password, hash) {
//         // login unsuccessful
//         return ...
//     }
//     // continue with logged in user
//
// This function accepts multiple hash formats for backwards compatibility.
func Verify(password, hash string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) < 4 {
		return false // not a supported format
	}
	switch {
	case strings.HasPrefix(hash, "$argon2id$v=19$") && len(parts) == 6:
		// Format emitted by the argon2 utility.
		return verifyArgon2(password, parts[3], parts[4], parts[5])
	case strings.HasPrefix(hash, "$argon2id$") && len(parts) == 5:
		// PHC string format.
		return verifyArgon2(password, parts[2], parts[3], parts[4])
	case strings.HasPrefix(hash, "$pbkdf2-sha256$") && len(parts) == 5:
		// Python hashlib format
		rawSalt, err := parseBase64(parts[3])
		if err != nil {
			return false
		}
		return verifyPBKDF2(sha256.New, password, parts[2], rawSalt, parts[4])
	case strings.HasPrefix(hash, "pbkdf2_sha256$") && len(parts) == 4:
		// Django format
		return verifyPBKDF2(sha256.New, password, parts[1], []byte(parts[2]), parts[3])
	default:
		// Unrecognized format.
		return false
	}
}

// verifyPBKDF2 checks whether the given PBKDF2 hash is valid and returns true
// iff the password matches the hash.
func verifyPBKDF2(hashFunc func() hash.Hash, password, iterations string, salt []byte, hash string) bool {
	iter, err := strconv.Atoi(iterations)
	if err != nil {
		return false
	}
	rawHash, err := parseBase64(hash)
	if err != nil {
		return false
	}

	key := pbkdf2.Key([]byte(password), []byte(salt), iter, len(rawHash), hashFunc)
	return subtle.ConstantTimeCompare(rawHash, key) == 1
}

// verifyArgon2 returns true iff the given password matches the argon2 hash.
func verifyArgon2(password, options, salt, hash string) bool {
	opts := parseOptions(options)
	if opts == nil {
		return false
	}
	rawHash, err := parseBase64(hash)
	if err != nil {
		return false
	}
	rawSalt, err := parseBase64(salt)
	if err != nil {
		return false
	}
	for _, k := range []string{"m", "t", "p"} {
		if _, ok := opts[k]; !ok {
			// Required key is not present in options.
			return false
		}
	}
	key := argon2.IDKey([]byte(password), rawSalt, uint32(opts["t"]), uint32(opts["m"]), uint8(opts["p"]), uint32(len(rawHash)))
	return subtle.ConstantTimeCompare(rawHash, key) == 1
}

// parseBase64 parses the given base64 string. It is able to decode any base64
// form in common use.
func parseBase64(s string) ([]byte, error) {
	// Strip off trailing '=' chars.
	s = strings.TrimRight(s, "=")

	// Use standard encoding (not URL encoding).
	s = strings.Replace(s, ".", "+", -1) // for MCF
	s = strings.Replace(s, "-", "+", -1)
	s = strings.Replace(s, "_", "/", -1)

	return base64.RawStdEncoding.DecodeString(s)
}

// parseOptions parses an option string like "m=65536,t=1,p=4" into its
// individual values: {"m": 65536, "t": 1, "p"=4}. A parse error results in a
// nil map.
func parseOptions(s string) map[string]int {
	parts := strings.Split(s, ",")
	opts := make(map[string]int)
	for _, part := range parts {
		index := strings.IndexByte(s, '=')
		if index < 0 {
			return nil
		}
		key := part[:index]
		value, err := strconv.Atoi(part[index+1:])
		if err != nil {
			return nil
		}
		if _, ok := opts[key]; ok {
			return nil // key already exists (invalid)
		}
		opts[key] = value
	}
	return opts
}
