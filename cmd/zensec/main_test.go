package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultOutputPath(t *testing.T) {
	cases := []struct {
		in      string
		encrypt bool
		want    string
		why     string
	}{
		{"secret.txt", true, "secret.txt.enc", "encryption appends .enc"},
		{"secret.txt", false, "secret.txt.dec", "decryption without .enc extension falls back to .dec"},
		{"secret.txt.enc", false, "secret.txt", "decryption strips the .enc extension"},
		{"archive.tar.gz.enc", false, "archive.tar.gz", "only a trailing .enc is stripped"},
		{"noext", true, "noext.enc", "encryption works on extensionless names"},
		{"UPPER.ENC", false, "UPPER.ENC.dec", "extension match is case sensitive, so this is not treated as encrypted"},
	}
	for _, c := range cases {
		if got := defaultOutputPath(c.in, c.encrypt); got != c.want {
			t.Errorf("defaultOutputPath(%q, encrypt=%v) = %q, want %q (%s)", c.in, c.encrypt, got, c.want, c.why)
		}
	}
}

func TestLoadKeyfile(t *testing.T) {
	dir := t.TempDir()

	t.Run("reads bytes verbatim", func(t *testing.T) {
		p := filepath.Join(dir, "key")
		if err := os.WriteFile(p, []byte("hunter2"), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := loadKeyfile(p)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "hunter2" {
			t.Errorf("got %q, want %q", got, "hunter2")
		}
	})

	t.Run("does not silently trim a trailing newline", func(t *testing.T) {
		// Trimming here would change the key of a file encrypted earlier and
		// turn a recoverable mistake into permanent data loss, so the bytes
		// must come back exactly as written.
		p := filepath.Join(dir, "key_nl")
		if err := os.WriteFile(p, []byte("hunter2\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := loadKeyfile(p)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "hunter2\n" {
			t.Errorf("trailing newline was altered: got %q, want %q", got, "hunter2\n")
		}
	})

	t.Run("rejects missing file", func(t *testing.T) {
		if _, err := loadKeyfile(filepath.Join(dir, "nope")); err == nil {
			t.Error("expected an error for a missing keyfile")
		}
	})

	t.Run("rejects empty file", func(t *testing.T) {
		p := filepath.Join(dir, "empty")
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadKeyfile(p); err == nil {
			t.Error("expected an error for an empty keyfile")
		}
	})

	t.Run("rejects a directory", func(t *testing.T) {
		if _, err := loadKeyfile(dir); err == nil {
			t.Error("expected an error when the keyfile is a directory")
		}
	})

	t.Run("rejects an oversized file", func(t *testing.T) {
		p := filepath.Join(dir, "big")
		f, err := os.Create(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(maxKeyfileBytes + 1); err != nil {
			t.Fatal(err)
		}
		f.Close()
		if _, err := loadKeyfile(p); err == nil {
			t.Errorf("expected an error for a keyfile larger than %d bytes", maxKeyfileBytes)
		}
	})
}

func TestRunRejectsBadInvocations(t *testing.T) {
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devnull.Close()

	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no mode", []string{"-file", "x"}, "exactly one of -encrypt or -decrypt"},
		{"both modes", []string{"-encrypt", "-decrypt", "-file", "x"}, "exactly one of -encrypt or -decrypt"},
		{"no file", []string{"-encrypt"}, "specify a file with -file"},
	}
	for _, c := range cases {
		var out, errb bytes.Buffer
		err := run(c.args, devnull, &out, &errb)
		if err == nil {
			t.Errorf("%s: expected an error", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %q, want it to contain %q", c.name, err, c.want)
		}
	}
}

func TestRunEncryptDecryptWithKeyfile(t *testing.T) {
	dir := t.TempDir()
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devnull.Close()

	key := filepath.Join(dir, "key")
	if err := os.WriteFile(key, []byte("a-strong-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	secret := []byte("the quick brown fox jumps over the lazy dog")
	src := filepath.Join(dir, "data.bin")
	if err := os.WriteFile(src, secret, 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errb bytes.Buffer
	if err := run([]string{"-encrypt", "-file", src, "-keyfile", key}, devnull, &out, &errb); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	enc := src + ".enc"
	if _, err := os.Stat(enc); err != nil {
		t.Fatalf("expected %s to exist: %v", enc, err)
	}
	if !strings.Contains(out.String(), "Encrypted") {
		t.Errorf("unexpected output: %q", out.String())
	}

	out.Reset()
	// -yes because the decrypt target is the original file, which exists.
	if err := run([]string{"-decrypt", "-file", enc, "-keyfile", key, "-yes"}, devnull, &out, &errb); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	got, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Errorf("round trip mismatch: %q", got)
	}
}

// TestWrongKeyfileLeavesFileIntact is the end-to-end guard for the original
// data-loss bug, exercised through the CLI rather than the library.
func TestWrongKeyfileLeavesFileIntact(t *testing.T) {
	dir := t.TempDir()
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devnull.Close()

	good := filepath.Join(dir, "good.key")
	bad := filepath.Join(dir, "bad.key")
	os.WriteFile(good, []byte("right-key"), 0o600)
	os.WriteFile(bad, []byte("wrong-key"), 0o600)

	secret := bytes.Repeat([]byte("important-"), 10000)
	src := filepath.Join(dir, "report.txt")
	os.WriteFile(src, secret, 0o600)

	var out, errb bytes.Buffer
	if err := run([]string{"-encrypt", "-file", src, "-keyfile", good}, devnull, &out, &errb); err != nil {
		t.Fatal(err)
	}

	// Decrypting with the wrong keyfile must fail *and* leave the existing
	// plaintext at its original path untouched.
	err = run([]string{"-decrypt", "-file", src + ".enc", "-keyfile", bad, "-yes"}, devnull, &out, &errb)
	if err == nil {
		t.Fatal("expected decryption with the wrong key to fail")
	}
	if !strings.Contains(err.Error(), "wrong password or tampered data") {
		t.Errorf("unhelpful error: %v", err)
	}

	got, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("original file was damaged: %d bytes on disk, want %d", len(got), len(secret))
	}
}

func TestConfirmOverwrite(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "there.txt")
	if err := os.WriteFile(existing, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "not-there.txt")

	var out bytes.Buffer
	var in bytes.Buffer

	ok, err := confirmOverwrite(&out, &in, missing)
	if err != nil || !ok {
		t.Errorf("missing file: got (%v, %v), want (true, nil)", ok, err)
	}

	in.Reset()
	in.WriteString("n\n")
	ok, err = confirmOverwrite(&out, &in, existing)
	if err != nil || ok {
		t.Errorf("declined: got (%v, %v), want (false, nil)", ok, err)
	}

	in.Reset()
	in.WriteString("y\n")
	ok, err = confirmOverwrite(&out, &in, existing)
	if err != nil || !ok {
		t.Errorf("accepted: got (%v, %v), want (true, nil)", ok, err)
	}

	in.Reset()
	ok, err = confirmOverwrite(&out, &in, existing)
	if err == nil {
		t.Errorf("no answer: got (%v, %v), want an error so automation cannot hang", ok, err)
	}
}
