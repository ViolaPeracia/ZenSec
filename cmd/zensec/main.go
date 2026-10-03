// Command zensec encrypts and decrypts local files.
//
//	zensec -encrypt -file PATH [-keyfile PATH] [-out PATH] [-yes]
//	zensec -decrypt -file PATH [-keyfile PATH] [-out PATH] [-yes]
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ViolaPeracia/ZenSec/internal/crypto"
	"golang.org/x/term"
)

// maxKeyfileBytes bounds how much data is accepted as key material. A keyfile is
// hashed, not used directly, so there is no reason to pull an entire disk image
// into memory.
const maxKeyfileBytes = 1 << 20 // 1 MiB

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "zensec: %v\n", err)
		os.Exit(1)
	}
}

type options struct {
	encrypt bool
	decrypt bool
	file    string
	keyfile string
	out     string
	yes     bool
}

// stdin is a *os.File because password entry needs a real terminal
// descriptor; non-interactive callers must use -keyfile.
func run(args []string, stdin *os.File, stdout, stderr io.Writer) error {
	var o options

	fs := flag.NewFlagSet("zensec", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.BoolVar(&o.encrypt, "encrypt", false, "encrypt the specified file")
	fs.BoolVar(&o.decrypt, "decrypt", false, "decrypt the specified file")
	fs.StringVar(&o.file, "file", "", "path to the target file")
	fs.StringVar(&o.keyfile, "keyfile", "", "use this file as key material instead of a password")
	fs.StringVar(&o.out, "out", "", "write the result to this path instead of the default")
	fs.BoolVar(&o.yes, "yes", false, "do not prompt before overwriting an existing file")

	fs.Usage = func() {
		fmt.Fprintf(stderr, "ZenSec - file encryption for AES-256-GCM with Argon2id key derivation\n\n")
		fmt.Fprintf(stderr, "Usage:\n  zensec -encrypt -file PATH [-keyfile PATH] [-out PATH] [-yes]\n  zensec -decrypt -file PATH [-keyfile PATH] [-out PATH] [-yes]\n\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}
	if o.encrypt == o.decrypt {
		fs.Usage()
		return errors.New("specify exactly one of -encrypt or -decrypt")
	}
	if o.file == "" {
		fs.Usage()
		return errors.New("specify a file with -file")
	}

	outPath := o.out
	if outPath == "" {
		outPath = defaultOutputPath(o.file, o.encrypt)
	}

	secret, err := readSecret(o.keyfile, stdin, stdout, o.encrypt)
	if err != nil {
		return err
	}
	defer crypto.Zeroize(secret)

	if !o.yes {
		ok, err := confirmOverwrite(stdout, stdin, outPath)
		if err != nil {
			return err
		}
		if !ok {
			fmt.Fprintf(stdout, "Cancelled. %s was not modified.\n", outPath)
			return nil
		}
	}

	if o.encrypt {
		if err := crypto.EncryptFile(o.file, outPath, secret); err != nil {
			return fmt.Errorf("encryption failed: %w", err)
		}
		fmt.Fprintf(stdout, "Encrypted %s -> %s\n", o.file, outPath)
		return nil
	}

	if err := crypto.DecryptFile(o.file, outPath, secret); err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}
	fmt.Fprintf(stdout, "Decrypted %s -> %s\n", o.file, outPath)
	return nil
}

// defaultOutputPath derives the output path when -out is not given.
func defaultOutputPath(inPath string, encrypt bool) string {
	if encrypt {
		return inPath + ".enc"
	}
	if trimmed := strings.TrimSuffix(inPath, ".enc"); trimmed != inPath {
		return trimmed
	}
	return inPath + ".dec"
}

// readSecret returns the key material, from a keyfile or an interactive prompt.
func readSecret(keyfile string, stdin *os.File, stdout io.Writer, confirm bool) ([]byte, error) {
	if keyfile != "" {
		return loadKeyfile(keyfile)
	}

	fd := int(stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, errors.New("no terminal available for password entry; use -keyfile for non-interactive use")
	}

	fmt.Fprint(stdout, "Password: ")
	pw, err := term.ReadPassword(fd)
	if err != nil {
		return nil, fmt.Errorf("could not read password: %w", err)
	}
	fmt.Fprintln(stdout)

	if !confirm {
		if len(pw) == 0 {
			return nil, errors.New("password cannot be empty")
		}
		return pw, nil
	}

	fmt.Fprint(stdout, "Confirm password: ")
	pw2, err := term.ReadPassword(fd)
	if err != nil {
		crypto.Zeroize(pw)
		return nil, fmt.Errorf("could not read password confirmation: %w", err)
	}
	fmt.Fprintln(stdout)
	defer crypto.Zeroize(pw2)

	if !bytes.Equal(pw, pw2) {
		crypto.Zeroize(pw)
		return nil, errors.New("passwords do not match")
	}
	if len(pw) == 0 {
		return nil, errors.New("password cannot be empty")
	}
	return pw, nil
}

// loadKeyfile reads key material from a file.
//
// The bytes are used verbatim: trailing whitespace is significant. This is
// deliberate, because silently trimming would change the key of a file that a
// user encrypted earlier, turning a recoverable situation into permanent data
// loss. A warning is printed instead, and the documentation tells users to
// create keyfiles with printf rather than echo.
func loadKeyfile(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("keyfile: %w", err)
	}
	if fi.IsDir() {
		return nil, fmt.Errorf("keyfile %s is a directory", path)
	}
	if fi.Size() > maxKeyfileBytes {
		return nil, fmt.Errorf("keyfile %s is %d bytes, limit is %d", path, fi.Size(), maxKeyfileBytes)
	}

	// #nosec G304 -- reading a user-supplied path is the documented -keyfile
	// feature; the size and directory checks above are the relevant guards.
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("keyfile: %w", err)
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("keyfile %s is empty", path)
	}
	if b[len(b)-1] == '\n' || b[len(b)-1] == '\r' {
		fmt.Fprintf(os.Stderr, "zensec: warning: keyfile %s ends with a newline; the newline is part of the key.\n"+
			"         Create keyfiles with printf 'secret' > key instead of echo.\n", path)
	}
	return b, nil
}

func confirmOverwrite(stdout io.Writer, stdin io.Reader, path string) (bool, error) {
	if _, err := os.Stat(path); err != nil {
		return true, nil // does not exist, nothing to overwrite
	}
	fmt.Fprintf(stdout, "%s already exists. Overwrite? [y/N]: ", filepath.Base(path))
	var response string
	if _, err := fmt.Fscanln(stdin, &response); err != nil {
		return false, errors.New("no confirmation given")
	}
	switch strings.ToLower(strings.TrimSpace(response)) {
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}
