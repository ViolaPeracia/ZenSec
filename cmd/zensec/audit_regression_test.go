package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// These are the exact scenarios the audit measured as failures. They exist so a
// regression shows up as a named test rather than as a surprise.

func TestAuditClosed_H1OriginalDataSurvivesWrongPassword(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.key")
	bad := filepath.Join(dir, "bad.key")
	os.WriteFile(good, []byte("correct-password"), 0o600)
	os.WriteFile(bad, []byte("WRONG-password"), 0o600)

	original := bytes.Repeat([]byte("TOPSECRET"), 20000) // 180000 bytes, 3 chunks
	src := filepath.Join(dir, "big.txt")
	os.WriteFile(src, original, 0o600)

	devnull, _ := os.Open(os.DevNull)
	defer devnull.Close()

	var out, errb bytes.Buffer
	if err := run([]string{"-encrypt", "-file", src, "-keyfile", good}, devnull, &out, &errb); err != nil {
		t.Fatal(err)
	}

	// Audit measured this: 180000 bytes -> 0 bytes.
	err := run([]string{"-decrypt", "-file", src + ".enc", "-keyfile", bad, "-yes"}, devnull, &out, &errb)
	if err == nil {
		t.Fatal("expected failure")
	}
	after, rerr := os.ReadFile(src)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if !bytes.Equal(after, original) {
		t.Fatalf("STILL BROKEN: %d bytes on disk, want %d", len(after), len(original))
	}
	t.Logf("audit measured 180000 -> 0 bytes; now %d -> %d bytes preserved", len(original), len(after))
}

func TestAuditClosed_H2BatchDecryptDoesNotWipeFolder(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "k")
	bad := filepath.Join(dir, "bad")
	os.WriteFile(good, []byte("k"), 0o600)
	os.WriteFile(bad, []byte("nope"), 0o600)

	devnull, _ := os.Open(os.DevNull)
	defer devnull.Close()
	var out, errb bytes.Buffer

	names := []string{"report.2024", "report.2025", "report.2026"}
	originals := map[string][]byte{}
	for _, n := range names {
		data := bytes.Repeat([]byte("real data for "+n+" "), 5000)
		originals[n] = data
		p := filepath.Join(dir, n)
		os.WriteFile(p, data, 0o600)
		if err := run([]string{"-encrypt", "-file", p, "-keyfile", good}, devnull, &out, &errb); err != nil {
			t.Fatal(err)
		}
	}

	// Audit measured this: all three files became 0 bytes.
	for _, n := range names {
		err := run([]string{"-decrypt", "-file", filepath.Join(dir, n+".enc"), "-keyfile", bad, "-yes"}, devnull, &out, &errb)
		if err == nil {
			t.Errorf("%s: expected failure", n)
		}
		after, rerr := os.ReadFile(filepath.Join(dir, n))
		if rerr != nil {
			t.Fatal(rerr)
		}
		if !bytes.Equal(after, originals[n]) {
			t.Errorf("STILL BROKEN: %s is %d bytes, want %d", n, len(after), len(originals[n]))
		}
	}
	t.Log("audit measured 3/3 files wiped to 0 bytes; all 3 now intact")
}

func TestAuditClosed_NoPartialPlaintextLeftOnDisk(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "k")
	os.WriteFile(key, []byte("k"), 0o600)

	devnull, _ := os.Open(os.DevNull)
	defer devnull.Close()
	var out, errb bytes.Buffer

	src := filepath.Join(dir, "doc")
	os.WriteFile(src, bytes.Repeat([]byte("D"), 300000), 0o600)
	if err := run([]string{"-encrypt", "-file", src, "-keyfile", key}, devnull, &out, &errb); err != nil {
		t.Fatal(err)
	}

	dst := filepath.Join(dir, "recovered")
	os.WriteFile(dst, []byte("PRECIOUS"), 0o600)

	// Tamper with chunk 2 so decryption fails after chunk 0 verified.
	raw, _ := os.ReadFile(src + ".enc")
	raw[54+65536+300] ^= 0xFF
	os.WriteFile(src+".enc", raw, 0o600)

	err := run([]string{"-decrypt", "-file", src + ".enc", "-keyfile", key, "-out", dst, "-yes"}, devnull, &out, &errb)
	if err == nil {
		t.Fatal("expected failure on tampered ciphertext")
	}

	// Audit measured 131072 bytes of partial plaintext left behind here.
	got, _ := os.ReadFile(dst)
	if !bytes.Equal(got, []byte("PRECIOUS")) {
		t.Fatalf("STILL BROKEN: destination holds %q, want the original PRECIOUS", got)
	}

	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("leftover temp file %s", e.Name())
		}
	}
}
