package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"math"
)

const (
	// Magic prefixes every ZenSec container.
	Magic = "ZSEC"

	// FormatVersion is the container version written by EncryptFile.
	FormatVersion byte = 2

	// legacyVersion is the original container. It is still decrypted for
	// backwards compatibility but is never written again.
	legacyVersion byte = 1

	// ChunkSize is the amount of plaintext covered by one AEAD tag. It is
	// written into the header so the value can evolve per file.
	ChunkSize = 64 * 1024

	// chunkSize is retained for the pre-v2 code paths and existing tests.
	chunkSize = ChunkSize

	saltSize      = 16
	baseNonceSize = 8

	// v2 header layout (54 bytes):
	//
	//	[0:4]   magic "ZSEC"
	//	[4]     container version
	//	[5]     KDF identifier (1 = Argon2id)
	//	[6:8]   Argon2 time cost
	//	[8:12]  Argon2 memory cost in KiB
	//	[12]    Argon2 parallelism
	//	[13]    header length in bytes
	//	[14:30] salt
	//	[30:38] per-file random nonce prefix
	//	[38:42] plaintext chunk size
	//	[42:50] total plaintext length
	//	[50:54] SHA-256(header[0:50])[:4] integrity tag
	headerV2Len = 54
	checksumLen = 4

	kdfArgon2id byte = 1

	// Bounds applied to KDF parameters read from a header before they are
	// handed to Argon2. Without these an attacker can craft a valid header
	// that makes DecryptFile allocate gigabytes and OOM the process.
	minArgonTime    = uint16(1)
	maxArgonTime    = uint16(64)
	minArgonMemory  = 8 * 1024 // 8 MiB
	maxArgonMemory  = 1024 * 1024
	maxArgonThreads = 64

	minChunkSize = 4 * 1024
	maxChunkSize = 16 * 1024 * 1024
)

var (
	// ErrInvalidFile means the container structure itself is unusable.
	ErrInvalidFile = errors.New("invalid or corrupted file")

	// ErrCorruptedHeader means the header failed its integrity check, so the
	// file was damaged or edited. It is deliberately distinct from
	// ErrDecryption so the caller can tell "this file is damaged" apart from
	// "this password is wrong".
	ErrCorruptedHeader = errors.New("file header is corrupted")

	// ErrUnsupportedVersion means the file was written by a newer ZenSec.
	ErrUnsupportedVersion = errors.New("unsupported container version")

	// ErrUnsupportedKDF means the key derivation function is not Argon2id.
	ErrUnsupportedKDF = errors.New("unsupported key derivation function")

	// ErrKDFParams means the header declares out-of-range KDF parameters.
	ErrKDFParams = errors.New("key derivation parameters out of range")

	// ErrFileTooLarge means the file needs more chunks than the nonce counter
	// can address.
	ErrFileTooLarge = errors.New("file too large for this container format")

	// ErrDecryption covers a failed AEAD tag check: either the password is
	// wrong or the ciphertext body was modified.
	ErrDecryption = errors.New("decryption failed (wrong password or tampered data)")
)

// Container is a parsed ZenSec file header plus everything needed to rebuild
// per-chunk nonces and associated data.
type Container struct {
	// Raw is the exact header as stored on disk. For v2 it is bound into every
	// chunk's associated data, which is what makes the header authenticated.
	Raw []byte

	Version   byte
	KDF       KDFParams
	Salt      []byte
	BaseNonce []byte
	ChunkSize int

	// chunkSize is the same value as ChunkSize in its serialised form. Keeping
	// both means the hot loop needs no int-to-uint conversion.
	chunkSize uint32

	// PlaintextSize is the exact length of the original data. Because the whole
	// header is bound into every chunk's associated data, this value is
	// authenticated, which is what makes truncation detectable at a chunk
	// boundary rather than only mid-chunk.
	//
	// It also means the plaintext length is disclosed in the container. That
	// is a deliberate trade: authenticated truncation detection is worth more
	// than hiding the file size, and it is the same trade 7-Zip and zip make.
	PlaintextSize uint64

	// legacy marks the v1 layout, where the header was not authenticated, the
	// nonce prefix was only 4 bytes, the sequence number was 8 bytes and the
	// plaintext length was not recorded at all.
	legacy bool
}

// NewContainer builds a v2 container description for a fresh encryption.
func NewContainer(kdf KDFParams, salt, baseNonce []byte, chunkSize uint32, plaintextSize uint64) *Container {
	h := encodeHeaderV2(kdf, salt, baseNonce, chunkSize, plaintextSize)
	return &Container{
		Raw:           h,
		Version:       FormatVersion,
		KDF:           kdf,
		Salt:          h[14:30],
		BaseNonce:     h[30:38],
		ChunkSize:     int(chunkSize),
		chunkSize:     chunkSize,
		PlaintextSize: plaintextSize,
	}
}

// ParseHeader reads and validates a container header, supporting both the
// current v2 layout and the legacy v1 layout.
func ParseHeader(r io.Reader) (*Container, error) {
	var pre [5]byte
	if _, err := io.ReadFull(r, pre[:]); err != nil {
		return nil, ErrInvalidFile
	}
	if !bytes.Equal(pre[0:4], []byte(Magic)) {
		return nil, ErrInvalidFile
	}

	switch pre[4] {
	case legacyVersion:
		return parseHeaderLegacy(r)
	case FormatVersion:
		return parseHeaderV2(r, pre[:])
	default:
		return nil, ErrUnsupportedVersion
	}
}

// parseHeaderLegacy reads the remaining 20 bytes of a 25-byte v1 header.
func parseHeaderLegacy(r io.Reader) (*Container, error) {
	rest := make([]byte, 20) // salt(16) + baseNonce(4)
	if _, err := io.ReadFull(r, rest); err != nil {
		return nil, ErrInvalidFile
	}

	raw := make([]byte, 0, 25)
	raw = append(raw, Magic...)
	raw = append(raw, legacyVersion)
	raw = append(raw, rest...)

	return &Container{
		Raw:       raw,
		Version:   legacyVersion,
		KDF:       legacyKDF(),
		Salt:      rest[0:16],
		BaseNonce: rest[16:20],
		ChunkSize: chunkSize,
		chunkSize: uint32(chunkSize),
		legacy:    true,
	}, nil
}

// parseHeaderV2 reads the remaining bytes of a v2 header and verifies the
// header integrity tag before any of its values are trusted.
func parseHeaderV2(r io.Reader, pre []byte) (*Container, error) {
	body := make([]byte, headerV2Len-5)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, ErrInvalidFile
	}

	raw := make([]byte, headerV2Len)
	copy(raw[0:5], pre)
	copy(raw[5:], body)

	if int(raw[13]) < headerV2Len {
		return nil, ErrInvalidFile
	}
	if raw[5] != kdfArgon2id {
		return nil, ErrUnsupportedKDF
	}

	sum := sha256.Sum256(raw[:headerV2Len-checksumLen])
	if !bytes.Equal(sum[:checksumLen], raw[headerV2Len-checksumLen:]) {
		return nil, ErrCorruptedHeader
	}

	c := &Container{
		Raw:     raw,
		Version: FormatVersion,
		KDF: KDFParams{
			Time:    binary.BigEndian.Uint16(raw[6:8]),
			Memory:  binary.BigEndian.Uint32(raw[8:12]),
			Threads: raw[12],
		},
		Salt:          raw[14:30],
		BaseNonce:     raw[30:38],
		chunkSize:     binary.BigEndian.Uint32(raw[38:42]),
		PlaintextSize: binary.BigEndian.Uint64(raw[42:50]),
	}
	c.ChunkSize = int(c.chunkSize)

	if err := c.KDF.validate(); err != nil {
		return nil, err
	}
	if c.ChunkSize < minChunkSize || c.ChunkSize > maxChunkSize {
		return nil, ErrInvalidFile
	}
	// A container must not claim more chunks than the nonce counter can reach.
	if c.chunkCount() >= uint64(c.MaxChunks()) {
		return nil, ErrFileTooLarge
	}
	return c, nil
}

// encodeHeaderV2 serialises a v2 header, including its integrity tag.
func encodeHeaderV2(kdf KDFParams, salt, baseNonce []byte, chunkSize uint32, plaintextSize uint64) []byte {
	h := make([]byte, headerV2Len)
	copy(h[0:4], Magic)
	h[4] = FormatVersion
	h[5] = kdfArgon2id
	binary.BigEndian.PutUint16(h[6:8], kdf.Time)
	binary.BigEndian.PutUint32(h[8:12], kdf.Memory)
	h[12] = kdf.Threads
	h[13] = headerV2Len
	copy(h[14:30], salt)
	copy(h[30:38], baseNonce)
	binary.BigEndian.PutUint32(h[38:42], chunkSize)
	binary.BigEndian.PutUint64(h[42:50], plaintextSize)

	sum := sha256.Sum256(h[:headerV2Len-checksumLen])
	copy(h[headerV2Len-checksumLen:], sum[:checksumLen])
	return h
}

// Nonce rebuilds the AEAD nonce for a chunk. Every chunk must receive a
// distinct nonce or GCM keystream reuse destroys confidentiality.
//
// v2 uses 8 random bytes per file plus a 32-bit counter, giving 2^64 distinct
// starting points instead of the 2^32 of v1. v1 keeps its original 4+8 split so
// existing files still decrypt.
func (c *Container) Nonce(seq uint32) []byte {
	n := make([]byte, 12)
	if c.legacy {
		copy(n[0:4], c.BaseNonce)
		binary.BigEndian.PutUint64(n[4:12], uint64(seq))
		return n
	}
	copy(n[0:8], c.BaseNonce)
	binary.BigEndian.PutUint32(n[8:12], seq)
	return n
}

// MaxChunks is the exclusive upper bound on chunk count. Version 2 addresses
// chunks with a 32-bit counter, which at the default chunk size is 2^32 chunks
// of 64 KiB, or 256 TiB. Version 1 carried a 64-bit counter in the container but
// is capped at the same limit here because the loop counter is shared.
func (c *Container) MaxChunks() uint32 {
	return math.MaxUint32
}

// LastChunk reports whether seq is the final chunk of this container.
func (c *Container) LastChunk(seq uint32) bool {
	if c.legacy {
		return false // decided from the read result instead
	}
	return uint64(seq)+1 >= c.chunkCount()
}

// chunkCount is how many chunks the recorded plaintext length needs.
func (c *Container) chunkCount() uint64 {
	n := c.PlaintextSize / uint64(c.chunkSize)
	if c.PlaintextSize%uint64(c.chunkSize) != 0 {
		n++
	}
	return n
}

// AAD builds the associated data for a chunk into dst.
//
// The v2 header is included so it is authenticated: tampering with the salt,
// the nonce prefix, the chunk size or any KDF parameter invalidates every
// chunk. The sequence number and the end-of-file marker are included so chunks
// cannot be reordered, duplicated, dropped or truncated.
//
// dst must have room for len(dst) + header bytes + 9 and is reused across chunks
// to keep a multi-gigabyte encryption allocation free.
func (c *Container) AAD(dst []byte, seq uint32, isLast bool) []byte {
	if !c.legacy {
		dst = append(dst, c.Raw...)
	}
	var s [8]byte
	binary.BigEndian.PutUint64(s[:], uint64(seq))
	dst = append(dst, s[:]...)
	if isLast {
		return append(dst, 1)
	}
	return append(dst, 0)
}
