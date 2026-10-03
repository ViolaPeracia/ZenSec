package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/crypto/argon2"
)

const testPassword = "correct horse battery staple"

// ---------------------------------------------------------------- helpers

func fixturePlaintext(size int) []byte {
	return bytes.Repeat([]byte("ZenSec-v1-fixture-block-"), 1+size/22)[:size]
}

// writeTempIn creates dir/name and fills it with data.
func writeTempIn(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// writeTemp overwrites an explicit path with data.
func writeTemp(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// assertTargetUntouched fails if a failed DecryptFile modified its destination.
// This is the regression guard for the original data-loss bug: DecryptFile used
// to truncate the destination before authenticating, so a wrong password wiped
// the plaintext that was already there.
func assertTargetUntouched(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("destination unreadable after failed decrypt: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("DESTINATION WAS CLOBBERED: want %d bytes of original data, file now holds %d bytes", len(want), len(got))
	}
}

// ------------------------------------------------------------ round trips

func TestEncryptDecryptRoundTrip(t *testing.T) {
	dir := t.TempDir()
	pw := []byte(testPassword)

	sizes := []int{0, 1, 2, 1023, 1024, 4096,
		ChunkSize - 1, ChunkSize, ChunkSize + 1,
		2 * ChunkSize, 2*ChunkSize + 1, 3*ChunkSize + 12345, 500000}

	for _, size := range sizes {
		data := fixturePlaintext(size)
		src := writeTempIn(t, dir, "in.bin", data)
		enc := filepath.Join(dir, "in.enc")
		out := filepath.Join(dir, "out.bin")

		if err := EncryptFile(src, enc, pw); err != nil {
			t.Fatalf("size %d: encrypt: %v", size, err)
		}
		if err := DecryptFile(enc, out, pw); err != nil {
			t.Fatalf("size %d: decrypt: %v", size, err)
		}
		if got := mustRead(t, out); !bytes.Equal(got, data) {
			t.Fatalf("size %d: round trip mismatch (%d vs %d bytes)", size, len(got), len(data))
		}
	}
}

// TestOverheadIsConstant pins the container overhead. Version 1 emitted a
// spurious tag-only chunk whenever the plaintext was an exact multiple of the
// chunk size, so the size jumps were visible; version 2 must be flat.
func TestOverheadIsConstant(t *testing.T) {
	dir := t.TempDir()
	pw := []byte(testPassword)

	for _, size := range []int{1, 4096, ChunkSize - 1, ChunkSize, ChunkSize + 1, 2 * ChunkSize, 2*ChunkSize + 1} {
		src := writeTempIn(t, dir, "in.bin", fixturePlaintext(size))
		enc := filepath.Join(dir, "in.enc")
		if err := EncryptFile(src, enc, pw); err != nil {
			t.Fatal(err)
		}
		got := len(mustRead(t, enc))
		chunks := (size + ChunkSize - 1) / ChunkSize
		if chunks == 0 {
			chunks = 1
		}
		want := headerV2Len + size + chunks*16 // header + plaintext + one GCM tag per chunk
		if got != want {
			t.Errorf("size %d: container = %d bytes, want %d", size, got, want)
		}
	}
}

// --------------------------------------------------------- data loss guard

func TestFailedDecryptLeavesDestinationUntouched(t *testing.T) {
	dir := t.TempDir()
	pw := []byte(testPassword)

	original := bytes.Repeat([]byte("IRREPLACEABLE-CONTENT-"), 9000) // multi-chunk
	src := writeTempIn(t, dir, "doc.txt", original)
	enc := filepath.Join(dir, "doc.txt.enc")
	dst := filepath.Join(dir, "doc.txt") // the real decrypt target

	if err := EncryptFile(src, enc, pw); err != nil {
		t.Fatal(err)
	}

	// wrong password
	if err := DecryptFile(enc, dst, []byte("wrong password")); err != ErrDecryption {
		t.Fatalf("wrong password: got %v, want ErrDecryption", err)
	}
	assertTargetUntouched(t, dst, original)

	// tampered body: damage chunk 2 of a multi-chunk file
	raw := mustRead(t, enc)
	raw[headerV2Len+ChunkSize+200] ^= 0xFF
	writeTemp(t, enc, raw)
	if err := DecryptFile(enc, dst, pw); err != ErrDecryption {
		t.Fatalf("tampered body: got %v, want ErrDecryption", err)
	}
	assertTargetUntouched(t, dst, original)
}

// TestNoTempFilesLeftBehind proves the atomic writer cleans up after itself on
// both success and failure.
func TestNoTempFilesLeftBehind(t *testing.T) {
	dir := t.TempDir()
	pw := []byte(testPassword)
	src := writeTempIn(t, dir, "in.bin", fixturePlaintext(200000))
	enc := filepath.Join(dir, "in.enc")
	out := filepath.Join(dir, "out.bin")

	if err := EncryptFile(src, enc, pw); err != nil {
		t.Fatal(err)
	}
	if err := DecryptFile(enc, out, []byte("wrong")); err == nil {
		t.Fatal("expected failure")
	}
	assertNoTemps(t, dir)
}

func assertNoTemps(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("leftover temporary file: %s", e.Name())
		}
	}
}

// --------------------------------------------------------------- integrity

func TestTruncationIsDetected(t *testing.T) {
	dir := t.TempDir()
	pw := []byte(testPassword)
	data := fixturePlaintext(3*ChunkSize + 999)
	src := writeTempIn(t, dir, "in.bin", data)
	enc := filepath.Join(dir, "in.enc")
	if err := EncryptFile(src, enc, pw); err != nil {
		t.Fatal(err)
	}
	full := mustRead(t, enc)
	bodyStart := headerV2Len
	chunk := ChunkSize + 16

	for _, drop := range []int{16, chunk, chunk + 16, 2 * chunk, 3 * chunk} {
		if len(full)-drop < bodyStart {
			continue
		}
		cut := filepath.Join(dir, "cut.enc")
		writeTemp(t, cut, full[:len(full)-drop])
		out := filepath.Join(dir, "cut.out")
		if err := DecryptFile(cut, out, pw); err == nil {
			t.Errorf("dropping %d bytes was NOT detected", drop)
		} else {
			t.Logf("drop %6d bytes -> %v", drop, err)
		}
	}
}

// TestBoundaryTruncationIsDetected covers the case that a read-result-driven
// end-of-file marker cannot catch: when the plaintext is an exact multiple of
// the chunk size, the final chunk fills the buffer completely and nothing about
// the read tells you it was last. Dropping whole trailing chunks from such a
// file must still fail, which the authenticated length in the header provides.
func TestBoundaryTruncationIsDetected(t *testing.T) {
	dir := t.TempDir()
	pw := []byte(testPassword)
	chunk := ChunkSize + 16

	for _, total := range []int{ChunkSize, 2 * ChunkSize, 3 * ChunkSize, 4 * ChunkSize} {
		src := writeTempIn(t, dir, fmt.Sprintf("in%d.bin", total), fixturePlaintext(total))
		enc := filepath.Join(dir, fmt.Sprintf("in%d.enc", total))
		if err := EncryptFile(src, enc, pw); err != nil {
			t.Fatal(err)
		}
		full := mustRead(t, enc)
		nchunks := (len(full) - headerV2Len) / chunk
		if nchunks != total/ChunkSize {
			t.Errorf("size %d: encrypted into %d chunks, want %d (no stray trailing chunk)", total, nchunks, total/ChunkSize)
		}

		for drop := 1; drop <= nchunks; drop++ {
			cut := filepath.Join(dir, fmt.Sprintf("cut%d_%d.enc", total, drop))
			writeTemp(t, cut, full[:len(full)-drop*chunk])
			out := filepath.Join(dir, fmt.Sprintf("cut%d_%d.out", total, drop))
			if err := DecryptFile(cut, out, pw); err == nil {
				t.Errorf("size %d: dropping %d whole trailing chunk(s) was NOT detected", total, drop)
			}
		}
	}
}

func TestChunkReorderingIsDetected(t *testing.T) {
	dir := t.TempDir()
	pw := []byte(testPassword)
	// four chunks so two full chunks can genuinely be swapped
	data := fixturePlaintext(4 * ChunkSize)
	src := writeTempIn(t, dir, "in.bin", data)
	enc := filepath.Join(dir, "in.enc")
	if err := EncryptFile(src, enc, pw); err != nil {
		t.Fatal(err)
	}
	raw := mustRead(t, enc)
	chunk := ChunkSize + 16

	// swap chunk 1 and chunk 2 (both full size, header untouched)
	a := headerV2Len + chunk // start of chunk 1
	b := a + chunk           // start of chunk 2
	swapped := make([]byte, len(raw))
	copy(swapped, raw)
	copy(swapped[a:b], raw[b:b+chunk]) // chunk 2 ciphertext into slot 1
	copy(swapped[b:b+chunk], raw[a:b]) // chunk 1 ciphertext into slot 2

	enc2 := filepath.Join(dir, "swapped.enc")
	writeTemp(t, enc2, swapped)
	out := filepath.Join(dir, "swapped.out")
	if err := DecryptFile(enc2, out, pw); err != ErrDecryption {
		t.Errorf("reordering: got %v, want ErrDecryption", err)
	}
}

func TestTrailingGarbageIsRejected(t *testing.T) {
	dir := t.TempDir()
	pw := []byte(testPassword)
	src := writeTempIn(t, dir, "in.bin", fixturePlaintext(5000))
	enc := filepath.Join(dir, "in.enc")
	if err := EncryptFile(src, enc, pw); err != nil {
		t.Fatal(err)
	}
	raw := append(mustRead(t, enc), bytes.Repeat([]byte{0xAA}, 64)...)
	enc2 := filepath.Join(dir, "appended.enc")
	writeTemp(t, enc2, raw)
	if err := DecryptFile(enc2, filepath.Join(dir, "o.bin"), pw); err != ErrDecryption {
		t.Errorf("appended garbage: got %v, want ErrDecryption", err)
	}
}

// --------------------------------------------------- header authentication

// TestHeaderFieldsAreAuthenticated flips every authenticated header field and
// requires a distinct, correct error. Version 1 had no header integrity at all,
// so a swapped salt or nonce prefix surfaced as a generic decryption failure
// that was indistinguishable from a wrong password.
func TestHeaderFieldsAreAuthenticated(t *testing.T) {
	dir := t.TempDir()
	pw := []byte(testPassword)
	src := writeTempIn(t, dir, "in.bin", fixturePlaintext(5000))
	base := filepath.Join(dir, "in.enc")
	if err := EncryptFile(src, base, pw); err != nil {
		t.Fatal(err)
	}
	raw := mustRead(t, base)

	cases := []struct {
		name string
		at   int
		want error
	}{
		{"magic", 0, ErrInvalidFile},
		{"version", 4, ErrUnsupportedVersion},
		{"kdf id", 5, ErrUnsupportedKDF},
		{"argon time", 6, ErrCorruptedHeader},
		{"argon memory", 8, ErrCorruptedHeader},
		{"argon threads", 12, ErrCorruptedHeader},
		{"header len", 13, ErrCorruptedHeader},
		{"salt", 14, ErrCorruptedHeader},
		{"nonce prefix", 30, ErrCorruptedHeader},
		{"chunk size", 38, ErrCorruptedHeader},
		{"plaintext size", 42, ErrCorruptedHeader},
		{"checksum", 50, ErrCorruptedHeader},
	}

	for _, c := range cases {
		tampered := append([]byte{}, raw...)
		tampered[c.at] ^= 0x01
		p := filepath.Join(dir, "t.enc")
		writeTemp(t, p, tampered)
		out := filepath.Join(dir, "t.out")
		err := DecryptFile(p, out, pw)
		if err != c.want {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
	}
}

// TestHostileKDFParamsAreRejected covers a denial-of-service vector introduced
// by storing KDF parameters in the header: a crafted header can carry a valid
// integrity tag, so the parameters must be range-checked before Argon2 runs.
// Without the clamp a 4 GiB memory cost would be allocated on every decrypt.
func TestHostileKDFParamsAreRejected(t *testing.T) {
	dir := t.TempDir()
	pw := []byte(testPassword)
	src := writeTempIn(t, dir, "in.bin", fixturePlaintext(1000))
	base := filepath.Join(dir, "in.enc")
	if err := EncryptFile(src, base, pw); err != nil {
		t.Fatal(err)
	}
	raw := mustRead(t, base)

	// rebuild the header with an out-of-range parameter and a *valid* tag
	rebuild := func(set func(h []byte)) []byte {
		h := append([]byte{}, raw...)
		set(h)
		sum := sha256.Sum256(h[:headerV2Len-checksumLen])
		copy(h[headerV2Len-checksumLen:], sum[:checksumLen])
		return h
	}

	cases := []struct {
		name string
		set  func(h []byte)
	}{
		{"memory = 4 GiB", func(h []byte) { binary.BigEndian.PutUint32(h[8:12], 4*1024*1024) }},
		{"memory = 0", func(h []byte) { binary.BigEndian.PutUint32(h[8:12], 0) }},
		{"memory = 4 GiB - 1", func(h []byte) { binary.BigEndian.PutUint32(h[8:12], 4*1024*1024-1) }},
		{"time = 65535", func(h []byte) { binary.BigEndian.PutUint16(h[6:8], 65535) }},
		{"threads = 255", func(h []byte) { h[12] = 255 }},
		{"chunk size = 0", func(h []byte) { binary.BigEndian.PutUint32(h[38:42], 0) }},
		{"chunk size = 2 GiB", func(h []byte) { binary.BigEndian.PutUint32(h[38:42], 2*1024*1024*1024) }},
	}

	for _, c := range cases {
		p := filepath.Join(dir, "hostile.enc")
		writeTemp(t, p, rebuild(c.set))
		out := filepath.Join(dir, "hostile.out")
		err := DecryptFile(p, out, pw)
		if err != ErrKDFParams && err != ErrInvalidFile {
			t.Errorf("%s: got %v, want ErrKDFParams or ErrInvalidFile", c.name, err)
		}
	}
}

func TestKDFValidation(t *testing.T) {
	good := DefaultKDF()
	if err := good.validate(); err != nil {
		t.Fatalf("DefaultKDF rejected: %v", err)
	}
	if good.Time < 2 || good.Memory < 19*1024 {
		t.Errorf("DefaultKDF is weaker than the OWASP baseline (t>=2, m>=19MiB): %+v", good)
	}

	bad := []KDFParams{
		{Time: 0, Memory: 65536, Threads: 4},
		{Time: maxArgonTime + 1, Memory: 65536, Threads: 4},
		{Time: 3, Memory: minArgonMemory - 1, Threads: 4},
		{Time: 3, Memory: maxArgonMemory + 1, Threads: 4},
		{Time: 3, Memory: 65536, Threads: 0},
		{Time: 3, Memory: 65536, Threads: maxArgonThreads + 1},
	}
	for _, k := range bad {
		if err := k.validate(); err != ErrKDFParams {
			t.Errorf("%+v: got %v, want ErrKDFParams", k, err)
		}
		if _, err := DeriveKey([]byte("pw"), bytes.Repeat([]byte{9}, saltSize), k); err != ErrKDFParams {
			t.Errorf("DeriveKey(%+v): got %v, want ErrKDFParams", k, err)
		}
	}
}

func TestDeriveKeyRejectsShortSalt(t *testing.T) {
	if _, err := DeriveKey([]byte("pw"), []byte("tiny"), DefaultKDF()); err == nil {
		t.Error("expected DeriveKey to reject a short salt")
	}
}

func TestDeriveKeyIsDeterministicAndSaltSeparated(t *testing.T) {
	saltA := bytes.Repeat([]byte{1}, saltSize)
	saltB := bytes.Repeat([]byte{2}, saltSize)
	kdf := DefaultKDF()

	a1, err := DeriveKey([]byte("pw"), saltA, kdf)
	if err != nil {
		t.Fatal(err)
	}
	a2, _ := DeriveKey([]byte("pw"), saltA, kdf)
	b, _ := DeriveKey([]byte("pw"), saltB, kdf)

	if !bytes.Equal(a1, a2) {
		t.Error("same password and salt produced different keys")
	}
	if bytes.Equal(a1, b) {
		t.Error("different salts produced the same key")
	}
	if len(a1) != keySize {
		t.Errorf("key length = %d, want %d", len(a1), keySize)
	}
}

func TestZeroizeClearsBytes(t *testing.T) {
	b := []byte("sensitive key material")
	Zeroize(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte %d was not cleared: %v", i, v)
		}
	}
}

func TestNoncePrefixIsWideEnough(t *testing.T) {
	dir := t.TempDir()
	pw := []byte(testPassword)
	src := writeTempIn(t, dir, "in.bin", []byte("x"))

	seen := map[[8]byte]bool{}
	for i := 0; i < 300; i++ {
		enc := filepath.Join(dir, "n.enc")
		if err := EncryptFile(src, enc, pw); err != nil {
			t.Fatal(err)
		}
		h := mustRead(t, enc)
		var p [8]byte
		copy(p[:], h[30:38])
		if seen[p] {
			t.Fatalf("nonce prefix repeated after %d files", i)
		}
		seen[p] = true
	}
	t.Logf("300 files, 300 distinct 8-byte nonce prefixes (v1 used only 4 bytes)")
}

func TestUniqueNoncePerChunk(t *testing.T) {
	c := NewContainer(DefaultKDF(), bytes.Repeat([]byte{1}, saltSize), bytes.Repeat([]byte{2}, baseNonceSize), uint32(ChunkSize), 1<<20)
	seen := map[string]bool{}
	for seq := uint32(0); seq < 5000; seq++ {
		n := string(c.Nonce(seq))
		if seen[n] {
			t.Fatalf("nonce reused at chunk %d", seq)
		}
		seen[n] = true
	}
}

// -------------------------------------------------------------- file modes

func TestOutputPermissionsArePrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no Unix permission bits; Chmod only toggles read-only and access is governed by ACLs")
	}
	dir := t.TempDir()
	pw := []byte(testPassword)
	src := writeTempIn(t, dir, "in.bin", fixturePlaintext(1000))
	enc := filepath.Join(dir, "in.enc")
	out := filepath.Join(dir, "out.bin")

	if err := EncryptFile(src, enc, pw); err != nil {
		t.Fatal(err)
	}
	if err := DecryptFile(enc, out, pw); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{enc, out} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if perm := fi.Mode().Perm(); perm != filePerm {
			t.Errorf("%s mode = %04o, want %04o", filepath.Base(p), perm, filePerm)
		}
	}
}

// ---------------------------------------------------------- self reference

func TestRefusesToOperateOnItself(t *testing.T) {
	dir := t.TempDir()
	pw := []byte(testPassword)
	src := writeTempIn(t, dir, "in.bin", fixturePlaintext(1000))

	if err := EncryptFile(src, src, pw); err == nil {
		t.Error("EncryptFile accepted an identical input and output path")
	}
	// and the source must still be intact
	if got := mustRead(t, src); len(got) != 1000 {
		t.Errorf("source was damaged: %d bytes", len(got))
	}
}

// ---------------------------------------------------- version 1 backwards compat

// legacyV1Encrypt is a transcription of the original version 1 EncryptFile.
//
// TestLegacyTranscriptionIsExact proves this transcription is byte-for-byte
// identical to the shipped version 1 code by reproducing the golden fixture from
// testdata, whose salt and nonce prefix are read straight out of the file. Only
// after that passes is the transcription trusted for the multi-chunk case.
func legacyV1Encrypt(t *testing.T, data []byte, salt, baseNonce []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	buf.WriteString("ZSEC")
	buf.WriteByte(1)
	buf.Write(salt)
	buf.Write(baseNonce)

	key := argon2.IDKey([]byte(testPassword), salt, 3, 64*1024, 4, keySize)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}

	plain := make([]byte, chunkSize)
	nonce := make([]byte, gcm.NonceSize())
	copy(nonce[0:4], baseNonce)
	rd := bytes.NewReader(data)

	for seq := uint64(0); ; seq++ {
		n, err := io.ReadFull(rd, plain)

		isLast := byte(0)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			isLast = 1
		} else if err != nil {
			t.Fatal(err)
		}

		aad := make([]byte, 9)
		binary.BigEndian.PutUint64(aad[0:8], seq)
		aad[8] = isLast
		binary.BigEndian.PutUint64(nonce[4:12], seq)

		buf.Write(gcm.Seal(nil, nonce, plain[:n], aad))
		if isLast == 1 {
			break
		}
	}
	return buf.Bytes()
}

func TestLegacyTranscriptionIsExact(t *testing.T) {
	golden := mustRead(t, filepath.Join("testdata", "v1_small.enc"))
	if string(golden[:5]) != "ZSEC\x01" {
		t.Fatalf("golden fixture is not a version 1 container: %q", golden[:5])
	}
	salt := golden[5:21]
	baseNonce := golden[21:25]

	got := legacyV1Encrypt(t, fixturePlaintext(4096), salt, baseNonce)
	if !bytes.Equal(got, golden) {
		t.Fatalf("transcription diverged from shipped v1 code: got %d bytes sha=%s, want %d bytes sha=%s",
			len(got), shaHex(got), len(golden), shaHex(golden))
	}
	t.Log("transcription reproduces the shipped version 1 output byte for byte")
}

func shaHex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:8])
}

func TestDecryptsVersion1Fixtures(t *testing.T) {
	cases := []struct {
		file string
		size int
	}{
		{"v1_small.enc", 4096},
		{"v1_multi.enc", 150000},
	}
	for _, c := range cases {
		dir := t.TempDir()
		src := filepath.Join(dir, c.file)
		writeFileBytes(t, src, mustRead(t, filepath.Join("testdata", c.file)))
		out := filepath.Join(dir, "out.bin")

		if err := DecryptFile(src, out, []byte(testPassword)); err != nil {
			t.Errorf("%s: decrypt: %v", c.file, err)
			continue
		}
		if got := mustRead(t, out); !bytes.Equal(got, fixturePlaintext(c.size)) {
			t.Errorf("%s: plaintext mismatch (%d vs %d bytes)", c.file, len(got), c.size)
		} else {
			t.Logf("%s (%d bytes) decrypted correctly under the v2 reader", c.file, c.size)
		}
	}
}

func writeFileBytes(t *testing.T, p string, b []byte) {
	t.Helper()
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestVersion1IntegrityStillChecked(t *testing.T) {
	dir := t.TempDir()
	raw := mustRead(t, filepath.Join("testdata", "v1_multi.enc"))

	// wrong password
	p1 := writeTempIn(t, filepath.Join(dir), "a.enc", raw)
	if err := DecryptFile(p1, filepath.Join(dir, "a.out"), []byte("nope")); err != ErrDecryption {
		t.Errorf("v1 wrong password: got %v, want ErrDecryption", err)
	}

	// truncation
	cut := raw[:len(raw)-16]
	p2 := writeTempIn(t, filepath.Join(dir), "b.enc", cut)
	if err := DecryptFile(p2, filepath.Join(dir, "b.out"), []byte(testPassword)); err != ErrDecryption {
		t.Errorf("v1 truncation: got %v, want ErrDecryption", err)
	}

	// tampering
	tam := append([]byte{}, raw...)
	tam[headerV2Len+100] ^= 0xFF
	p3 := writeTempIn(t, filepath.Join(dir), "c.enc", tam)
	if err := DecryptFile(p3, filepath.Join(dir, "c.out"), []byte(testPassword)); err != ErrDecryption {
		t.Errorf("v1 tampering: got %v, want ErrDecryption", err)
	}
}

// ------------------------------------------------------------ key derivation

func TestKDFParamsRoundTripThroughHeader(t *testing.T) {
	dir := t.TempDir()
	pw := []byte(testPassword)
	src := writeTempIn(t, dir, "in.bin", fixturePlaintext(1000))
	enc := filepath.Join(dir, "in.enc")
	if err := EncryptFile(src, enc, pw); err != nil {
		t.Fatal(err)
	}
	h := mustRead(t, enc)

	c, err := ParseHeader(bytes.NewReader(h))
	if err != nil {
		t.Fatal(err)
	}
	if c.KDF != DefaultKDF() {
		t.Errorf("header KDF = %+v, want %+v", c.KDF, DefaultKDF())
	}
	if c.ChunkSize != ChunkSize {
		t.Errorf("header chunk size = %d, want %d", c.ChunkSize, ChunkSize)
	}
	if c.Version != FormatVersion {
		t.Errorf("version = %d, want %d", c.Version, FormatVersion)
	}
	if c.legacy {
		t.Error("new container reported as legacy")
	}
}

func TestDifferentPasswordsProduceDifferentKeys(t *testing.T) {
	dir := t.TempDir()
	data := fixturePlaintext(1000)
	a := writeTempIn(t, dir, "a.bin", data)
	b := writeTempIn(t, dir, "b.bin", data)

	ea, eb := filepath.Join(dir, "a.enc"), filepath.Join(dir, "b.enc")
	if err := EncryptFile(a, ea, []byte("pw1")); err != nil {
		t.Fatal(err)
	}
	if err := EncryptFile(b, eb, []byte("pw2")); err != nil {
		t.Fatal(err)
	}
	// bodies must not match: different keys, different nonces, different salts
	if bytes.Equal(mustRead(t, ea)[headerV2Len:], mustRead(t, eb)[headerV2Len:]) {
		t.Error("two encryptions with different passwords produced identical bodies")
	}
}

func TestSaltAndNonceAreFreshPerFile(t *testing.T) {
	dir := t.TempDir()
	pw := []byte(testPassword)
	src := writeTempIn(t, dir, "in.bin", []byte("x"))

	salts := map[string]bool{}
	nonces := map[string]bool{}
	for i := 0; i < 200; i++ {
		enc := filepath.Join(dir, "n.enc")
		if err := EncryptFile(src, enc, pw); err != nil {
			t.Fatal(err)
		}
		h := mustRead(t, enc)
		salts[string(h[14:30])] = true
		nonces[string(h[30:38])] = true
	}
	if len(salts) != 200 {
		t.Errorf("only %d/200 distinct salts", len(salts))
	}
	if len(nonces) != 200 {
		t.Errorf("only %d/200 distinct nonce prefixes", len(nonces))
	}
}

// ------------------------------------------------------------- robustness

func TestMalformedInputNeverPanics(t *testing.T) {
	dir := t.TempDir()
	good := func() []byte {
		src := writeTempIn(t, dir, "g.bin", fixturePlaintext(3000))
		e := filepath.Join(dir, "g.enc")
		if err := EncryptFile(src, e, []byte(testPassword)); err != nil {
			t.Fatal(err)
		}
		return mustRead(t, e)
	}()
	g := good

	inputs := [][]byte{
		{},
		[]byte("ZSEC"),
		[]byte("ZSEC\x02"),
		bytes.Repeat([]byte{0}, 46),
		bytes.Repeat([]byte{0xff}, 46),
		g[:headerV2Len-1],
		g[:headerV2Len],
		g[:headerV2Len+1],
		g,
		append(append([]byte{}, g...), 1, 2, 3),
		bytes.Repeat([]byte("ZSEC\x02"), 20000),
	}

	for i, in := range inputs {
		p := filepath.Join(dir, "m.enc")
		writeFileBytes(t, p, in)
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("input %d panicked: %v", i, r)
				}
			}()
			if err := DecryptFile(p, filepath.Join(dir, "m.out"), []byte("pw")); err == nil && i != 8 {
				t.Errorf("input %d unexpectedly decrypted", i)
			}
		}()
	}
}

func TestRefusesUnreadablePaths(t *testing.T) {
	dir := t.TempDir()
	pw := []byte(testPassword)
	missing := filepath.Join(dir, "nope.bin")

	if err := EncryptFile(missing, filepath.Join(dir, "o.enc"), pw); err == nil {
		t.Error("EncryptFile accepted a missing input")
	}
	if err := DecryptFile(missing, filepath.Join(dir, "o.bin"), pw); err == nil {
		t.Error("DecryptFile accepted a missing input")
	}
}

func TestEmptyPasswordStillDerivesKey(t *testing.T) {
	dir := t.TempDir()
	data := fixturePlaintext(500)
	src := writeTempIn(t, dir, "in.bin", data)
	enc := filepath.Join(dir, "in.enc")
	out := filepath.Join(dir, "out.bin")

	// The CLI rejects an empty password, but the crypto layer must not panic
	// or produce something undecryptable.
	if err := EncryptFile(src, enc, nil); err != nil {
		t.Fatal(err)
	}
	if err := DecryptFile(enc, out, nil); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mustRead(t, out), data) {
		t.Error("empty password round trip failed")
	}
}

// ------------------------------------------------------------------- fuzz

func FuzzDecryptFile(f *testing.F) {
	f.Add(bytes.Repeat([]byte{0}, 0))
	f.Add([]byte("ZSEC\x01"))
	f.Add([]byte("ZSEC\x02"))
	f.Add([]byte("ZSEC\x99"))
	f.Add(bytes.Repeat([]byte{0xff}, 64))
	f.Add(bytes.Repeat([]byte{0x41}, 46))
	f.Add(bytes.Repeat([]byte{0x41}, 47))
	f.Add(append(bytes.Repeat([]byte("ZSEC\x02"), 4), 0xff))

	dir := f.TempDir()
	src := filepath.Join(dir, "seed.bin")
	if err := os.WriteFile(src, fixturePlaintext(5000), 0o644); err != nil {
		f.Fatal(err)
	}
	enc := filepath.Join(dir, "seed.enc")
	if err := EncryptFile(src, enc, []byte(testPassword)); err != nil {
		f.Fatal(err)
	}
	seed, err := os.ReadFile(enc)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)

	f.Fuzz(func(t *testing.T, data []byte) {
		in := filepath.Join(t.TempDir(), "in.enc")
		out := filepath.Join(t.TempDir(), "out.bin")
		if err := os.WriteFile(in, data, 0o644); err != nil {
			t.Skip()
		}
		// The only contract is: never panic, and if it reports success the
		// output must be readable.
		if err := DecryptFile(in, out, []byte(testPassword)); err != nil {
			return
		}
		if _, err := os.Stat(out); err != nil {
			t.Fatalf("decrypt reported success but produced no file: %v", err)
		}
	})
}
