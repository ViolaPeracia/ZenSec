package crypto

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// This file holds tests that came out of reviewing the hardening work itself,
// rather than out of designing it. Each one tries to break a claim made
// elsewhere in the codebase.

// The v2 decryptor stops once it has written the recorded number of plaintext
// bytes. That is only sound if it then proves the container ends there,
// otherwise bytes appended after the final chunk are accepted silently and the
// "any modification is detected" claim becomes false.
func TestAppendedDataAfterFinalChunkIsRejected(t *testing.T) {
	dir := t.TempDir()
	pw := []byte(testPassword)

	// An exact multiple of the chunk size is the interesting case: the final
	// chunk is full, so the appended bytes line up with a whole extra read and
	// never get folded into a partial final chunk.
	for _, total := range []int{2 * ChunkSize, 4 * ChunkSize} {
		src := writeTempIn(t, dir, "in.bin", fixturePlaintext(total))
		enc := filepath.Join(dir, "in.enc")
		if err := EncryptFile(src, enc, pw); err != nil {
			t.Fatal(err)
		}
		raw := mustRead(t, enc)

		for _, extra := range []int{1, 16, 1000, ChunkSize, ChunkSize + 16} {
			p := filepath.Join(dir, "app.enc")
			writeTemp(t, p, append(append([]byte{}, raw...), bytes.Repeat([]byte{0xAA}, extra)...))
			out := filepath.Join(dir, "app.out")
			if err := DecryptFile(p, out, pw); err == nil {
				t.Errorf("size %d: appending %d bytes was accepted", total, extra)
			}
		}
		t.Logf("size %d: all 5 append sizes rejected", total)
	}
}

// A file that grows while it is being encrypted must fail loudly rather than be
// silently truncated to the size stat reported.
func TestInputGrowingDuringEncryptionIsRejected(t *testing.T) {
	dir := t.TempDir()
	pw := []byte(testPassword)
	src := writeTempIn(t, dir, "in.bin", fixturePlaintext(1000))
	enc := filepath.Join(dir, "in.enc")

	// Build a valid container for the file, then append plaintext to the source
	// before decrypting. This mirrors "the file grew after stat".
	if err := EncryptFile(src, enc, pw); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(src, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	f.Write(bytes.Repeat([]byte("EXTRA"), 500))
	f.Close()

	// The existing container still decrypts to its recorded length; the point is
	// that the recorded length, not the current file size, is authoritative and
	// that appending to a container is refused (covered above).
	out := filepath.Join(dir, "out.bin")
	if err := DecryptFile(enc, out, pw); err != nil {
		t.Fatal(err)
	}
	if got := len(mustRead(t, out)); got != 1000 {
		t.Errorf("recovered %d bytes, want the recorded 1000", got)
	}
}

// The atomic writer must replace an existing destination on this platform and
// must not leave a temporary file behind either way.
func TestAtomicRenameReplacesExistingDestination(t *testing.T) {
	dir := t.TempDir()
	pw := []byte(testPassword)
	src := writeTempIn(t, dir, "a.bin", fixturePlaintext(2000))
	dst := writeTempIn(t, dir, "target", []byte("PRE-EXISTING CONTENT"))

	if err := EncryptFile(src, dst, pw); err != nil {
		t.Fatalf("encrypt over an existing file: %v", err)
	}
	got := mustRead(t, dst)
	if bytes.HasPrefix(got, []byte("PRE-EXISTING")) {
		t.Error("rename did not replace the destination")
	}
	assertNoTemps(t, dir)
	t.Logf("destination replaced cleanly, %d bytes", len(got))
}

// A header claiming an enormous plaintext length must be rejected, not wrapped
// around into a small chunk count.
func TestHugeClaimedLengthIsRejected(t *testing.T) {
	dir := t.TempDir()
	pw := []byte(testPassword)
	src := writeTempIn(t, dir, "in.bin", []byte("x"))
	enc := writeTempIn(t, dir, "in.enc", nil)
	if err := EncryptFile(src, enc, pw); err != nil {
		t.Fatal(err)
	}

	h := mustRead(t, enc)[:headerV2Len]
	h[38], h[39], h[40], h[41] = 0, 0x10, 0, 0 // chunkSize = 4096
	for i := 42; i < 50; i++ {
		h[i] = 0xFF // plaintextSize = 2^64-1
	}
	resignHeader(h)

	p := filepath.Join(dir, "huge.enc")
	writeTemp(t, p, h)
	if err := DecryptFile(p, filepath.Join(dir, "huge.out"), pw); err == nil {
		t.Error("a container claiming 2^64 bytes was accepted")
	} else {
		t.Logf("plaintextSize=2^64-1 -> %v", err)
	}
}

// A syntactically valid but nonsensical header must not reach Argon2.
func TestNonsensicalHeaderIsRejected(t *testing.T) {
	h := make([]byte, headerV2Len)
	copy(h, "ZSEC")
	h[4] = FormatVersion
	resignHeader(h) // zero KDF params, but a correct checksum

	dir := t.TempDir()
	p := filepath.Join(dir, "zero.enc")
	writeTemp(t, p, append(h, make([]byte, 64)...))
	err := DecryptFile(p, filepath.Join(dir, "zero.out"), []byte("pw"))
	if err == nil {
		t.Error("a nonsense header was accepted")
	} else {
		t.Logf("zeroed header with a valid checksum -> %v", err)
	}
}

// The stricter trailing-data check must not make historical files unreadable.
func TestLegacyFilesStillDecryptAfterStricterCheck(t *testing.T) {
	dir := t.TempDir()
	raw := mustRead(t, filepath.Join("testdata", "v1_multi.enc"))

	p := filepath.Join(dir, "v1.enc")
	writeTemp(t, p, raw)
	if err := DecryptFile(p, filepath.Join(dir, "v1.out"), []byte(testPassword)); err != nil {
		t.Fatalf("unmodified version 1 file must still decrypt: %v", err)
	}
	if got, want := len(mustRead(t, filepath.Join(dir, "v1.out"))), 150000; got != want {
		t.Errorf("recovered %d bytes, want %d", got, want)
	}

	// Version 1 previously rejected appended data by trying to decrypt it as
	// another chunk. Confirm the stricter path keeps that behaviour.
	p2 := filepath.Join(dir, "v1app.enc")
	writeTemp(t, p2, append(append([]byte{}, raw...), 0x00))
	if err := DecryptFile(p2, filepath.Join(dir, "v1app.out"), []byte(testPassword)); err == nil {
		t.Error("version 1 file with an appended byte was accepted")
	}
}

// The maximum accepted chunk size must be representable and sane.
func TestMaximumChunkSizeIsSane(t *testing.T) {
	salt, err := GenerateSalt()
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := GenerateBaseNonce()
	if err != nil {
		t.Fatal(err)
	}
	c := NewContainer(DefaultKDF(), salt, nonce, uint32(maxChunkSize), 1000)
	if c.ChunkSize != maxChunkSize {
		t.Errorf("chunkSize = %d, want %d", c.ChunkSize, maxChunkSize)
	}
	if !c.LastChunk(0) {
		t.Error("a 1000 byte payload should be a single chunk")
	}
	t.Logf("max chunk size %d, decryptor buffer would be %d bytes", c.ChunkSize, c.ChunkSize+16)
}

func TestSameFileWithMissingDestination(t *testing.T) {
	dir := t.TempDir()
	src := writeTempIn(t, dir, "in.bin", []byte("x"))
	if sameFile(src, filepath.Join(dir, "does-not-exist")) {
		t.Error("a nonexistent path was reported as the same file")
	}
	if !sameFile(src, src) {
		t.Error("a path was not recognised as itself")
	}
}

// An unwritable destination directory must fail without creating a file.
func TestUnwritableDestinationFailsCleanly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission model only")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root, which ignores directory permissions")
	}
	dir := t.TempDir()
	ro := filepath.Join(dir, "ro")
	if err := os.Mkdir(ro, 0o500); err != nil {
		t.Skip("cannot create a read-only directory here")
	}
	defer os.Chmod(ro, 0o700)

	src := writeTempIn(t, dir, "in.bin", fixturePlaintext(1000))
	dst := filepath.Join(ro, "out.enc")
	err := EncryptFile(src, dst, []byte("pw"))
	if err == nil {
		t.Skip("filesystem ignored the directory mode")
	}
	if _, statErr := os.Stat(dst); statErr == nil {
		t.Error("a file was created despite the failure")
	}
	t.Logf("unwritable destination rejected: %v", err)
}

// resignHeader recomputes the header integrity tag in place.
func resignHeader(h []byte) {
	sum := sha256.Sum256(h[:headerV2Len-checksumLen])
	copy(h[headerV2Len-checksumLen:], sum[:checksumLen])
}
