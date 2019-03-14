# Opinionated password hashing library

[![GoDoc](https://godoc.org/github.com/aykevl/pwhash?status.svg)](https://godoc.org/github.com/aykevl/pwhash)
[![CircleCI](https://circleci.com/gh/aykevl/pwhash.svg?style=svg)](https://circleci.com/gh/aykevl/pwhash)

This library implements password hashing functions for Go web applications. It
is intentionally not configurable to avoid security mistakes.

Using it is very simple. There are only two methods: `Hash` and `Verify`:

```go
// When storing a password in the database:
password := "correct horse battery staple"
hash := pwhash.Hash(password)

// When checking a password for validity:
if !pwhash.Verify(password, hash) {
	// Oh no, the user entered the wrong password!
	showLoginPage()
	return
}
// User is logged in. Set up a session etc.
```

In the current configuration, it hashes passwords using argon2id, with 64MB
memory, a time parameter of 1, and uses 4 threads. Passwords hashed this way
should take under 50ms to verify on most systems.

Some other password formats are supported for backwards compatibility. This
includes the PBKDF2-SHA256 hash in the Python hashlib and the Django format.
More formats can be added if the need arises. Remember that this is only for
legacy purposes, newly stored passwords will be in the argon2 format and thus
better protected against cracking.

## License

This library has been put into the public domain. For details, see `LICENSE.txt`
or [unlicense.org](https://unlicense.org).
