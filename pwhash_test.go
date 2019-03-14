package pwhash

import (
	"fmt"
	"strconv"
	"testing"
)

func ExampleHash() {
	hash := Hash("correct horse battery staple")
	fmt.Println("hash:", hash)

	fmt.Println("verify:", Verify("correct horse battery staple", hash))
	fmt.Println("verify:", Verify("Tr0ub4dor&3", hash))
}

func TestVerify(t *testing.T) {
	for _, hash := range []string{
		"$argon2id$v=19$m=4096,t=3,p=1$dGhpc2lzbXlzYWx0$AzZgJAmUX0qrUmnwTqjOwOVbjPqyWyUpVBcro6+iDtk",  // argon2 utility
		"$argon2id$v=19$m=65536,t=1,p=4$dGhpc2lzbXlzYWx0$iLIET3ndAQM+9lCpSzdouD8JssU10/yKZSe46oawE1E", // argon2 utility
		"pbkdf2_sha256$29000$J7TQfLFWTkpn$QoF0Op8EhgreLpM1MQEMSeKmnTWeGcn49gI6d01wvI4=",               // Django
		"$pbkdf2-sha256$29000$YKz13rt3bo3xntPa29u7lw$IPZ5wVv4mVrYdjnBX04eDAtCO2unwPMWcdZQ.6z0ns8",     // Python hashlib
	} {
		if !Verify("password", hash) {
			t.Log("hash did not verify:", hash)
			t.Fail()
		}
		if Verify("passworD", hash) {
			t.Log("hash incorrectly verified:", hash)
			t.Fail()
		}
	}
}

func TestHash(t *testing.T) {
	for i := 0; i < 10; i++ {
		hash := Hash("password")
		if !Verify("password", hash) {
			t.Log("password did not roundtrip with hash", hash)
			t.Fail()
		}
		if Verify("passworD", hash) {
			t.Log("password was incorrectly verified with hash", hash)
			t.Fail()
		}
	}
}

var benchmarkHash string

func BenchmarkHash(b *testing.B) {
	password := strconv.Itoa(b.N)
	for i := 0; i < b.N; i++ {
		benchmarkHash = Hash(password)
	}
}
