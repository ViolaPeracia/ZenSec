package crypto

import (
	"crypto/rand"
	"errors"
	"runtime"

	"golang.org/x/crypto/argon2"
)

const (
	keySize = 32
)

// KDFParams records the Argon2id cost parameters used for one file. They are
// stored in the container header so future versions can raise the cost without
// orphaning files that are already encrypted.
//
// Time is uint16 because that is what the header field holds and because the
// validated range (1..64) is far inside it; widening to Argon2's uint32 is then
// provably safe.
type KDFParams struct {
	Time    uint16
	Memory  uint32 // KiB
	Threads uint8
}

// DefaultKDF returns the parameters used for newly created files.
//
// 64 MiB / 3 passes / 4 lanes is comfortably above the OWASP baseline
// (19 MiB, t=2, p=1) and is the historical ZenSec setting, so upgrading is an
// explicit, audited change rather than a silent one.
func DefaultKDF() KDFParams {
	t := uint8(4)
	if n := runtime.NumCPU(); n > 0 && n < 256 {
		t = uint8(n)
	}
	if t == 0 {
		t = 1
	}
	return KDFParams{Time: 3, Memory: 64 * 1024, Threads: t}
}

// legacyKDF reproduces the hardcoded parameters that version 1 containers were
// always created with. Decrypting a v1 file must use these exact values.
func legacyKDF() KDFParams {
	return KDFParams{Time: 3, Memory: 64 * 1024, Threads: 4}
}

// validate rejects parameter sets that are out of range or would let a hostile
// header drive an unreasonable allocation.
func (k KDFParams) validate() error {
	if k.Time < minArgonTime || k.Time > maxArgonTime {
		return ErrKDFParams
	}
	if k.Memory < minArgonMemory || k.Memory > maxArgonMemory {
		return ErrKDFParams
	}
	if k.Threads < 1 || k.Threads > maxArgonThreads {
		return ErrKDFParams
	}
	return nil
}

// DeriveKey derives a 32-byte AES key from a password and salt using Argon2id.
func DeriveKey(password, salt []byte, kdf KDFParams) ([]byte, error) {
	if err := kdf.validate(); err != nil {
		return nil, err
	}
	if len(salt) < 8 {
		return nil, errors.New("salt is too short")
	}
	return argon2.IDKey(password, salt, uint32(kdf.Time), kdf.Memory, kdf.Threads, keySize), nil
}

// GenerateSalt returns a random per-file salt.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// GenerateBaseNonce returns the random per-file nonce prefix. v2 uses 8 bytes
// (64 bits) rather than v1's 4 bytes so that per-file nonce collisions stay
// negligible for realistic collection sizes.
func GenerateBaseNonce() ([]byte, error) {
	n := make([]byte, baseNonceSize)
	if _, err := rand.Read(n); err != nil {
		return nil, err
	}
	return n, nil
}

// zeroize overwrites b with zeros. The Go compiler is allowed to elide stores
// to a slice that is never read again, so this narrows the window in which key
// material sits in memory but does not close it completely.
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Zeroize overwrites b with zeros. It is exported so the CLI can clear the
// password it read, which lives outside this package.
func Zeroize(b []byte) { zeroize(b) }
