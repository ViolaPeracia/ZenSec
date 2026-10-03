package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// filePerm is the permission mask for both ciphertext and, more importantly,
// recovered plaintext. os.Create would use 0666 which leaves decrypted secrets
// readable by every account on the machine.
const filePerm os.FileMode = 0o600

// EncryptFile encrypts the file at inPath and writes the result to outPath.
//
// The output is produced atomically: bytes land in a temporary file next to
// outPath and are only renamed into place after the last chunk has been
// written. If anything fails, outPath is left exactly as it was.
func EncryptFile(inPath, outPath string, password []byte) error {
	inFile, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer inFile.Close()

	if sameFile(inPath, outPath) {
		return errors.New("refusing to encrypt a file onto itself")
	}

	salt, err := GenerateSalt()
	if err != nil {
		return err
	}
	baseNonce, err := GenerateBaseNonce()
	if err != nil {
		return err
	}

	fi, err := inFile.Stat()
	if err != nil {
		return err
	}
	if fi.Size() < 0 {
		return ErrInvalidFile
	}
	// #nosec G115 -- the negative case is rejected on the line above and
	// os.FileInfo sizes are never negative in practice.
	plaintextSize := uint64(fi.Size())

	kdf := DefaultKDF()
	key, err := DeriveKey(password, salt, kdf)
	if err != nil {
		return err
	}
	defer zeroize(key)

	aead, err := newAEAD(key)
	if err != nil {
		return err
	}

	c := NewContainer(kdf, salt, baseNonce, uint32(ChunkSize), plaintextSize)

	return atomicWrite(outPath, func(w io.Writer) error {
		if _, err := w.Write(c.Raw); err != nil {
			return err
		}

		buf := make([]byte, c.ChunkSize)
		var aad []byte
		nonce := make([]byte, aead.NonceSize())

		for seq := uint32(0); seq < c.MaxChunks(); seq++ {
			n, rerr := io.ReadFull(inFile, buf)
			if rerr != nil && rerr != io.EOF && rerr != io.ErrUnexpectedEOF {
				return rerr
			}

			// Which chunk is last is decided from the recorded length, not from
			// the read result. A read result cannot distinguish a chunk that
			// exactly filled the buffer from one that was followed by more
			// data, so relying on it leaves a plaintext whose size is an exact
			// multiple of the chunk size with no end-of-file marker at all,
			// and truncation at that boundary would decrypt silently.
			isLast := c.LastChunk(seq)

			copy(nonce, c.Nonce(seq))
			aad = c.AAD(aad[:0], seq, isLast)

			if _, err := w.Write(aead.Seal(nil, nonce, buf[:n], aad)); err != nil {
				return err
			}
			if isLast {
				// The recorded length only tells us how much to expect, not
				// that the container ends there.
				if err := requireEOF(inFile); err != nil {
					return err
				}
				return nil
			}
			// Input ended before the recorded length, so the file shrank
			// underneath us between stat and read.
			if rerr != nil {
				return ErrInvalidFile
			}
		}
		return ErrFileTooLarge
	})
}

// requireEOF fails unless the reader is exhausted.
//
// It is called once the expected number of bytes has been processed. Without it
// a container could carry arbitrary extra bytes after its final chunk and still
// decrypt cleanly, which would contradict the property the format exists to
// provide: any modification to the ciphertext is detected.
//
// It also catches a file that grew while it was being encrypted, which would
// otherwise be silently truncated to the size observed by stat.
func requireEOF(r io.Reader) error {
	var probe [1]byte
	n, err := r.Read(probe[:])
	if n > 0 {
		return ErrDecryption
	}
	if err != nil && err != io.EOF {
		return err
	}
	return nil
}

// DecryptFile decrypts the file at inPath and writes the plaintext to outPath.
//
// Like EncryptFile the write is atomic, so a wrong password or a tampered file
// leaves outPath untouched instead of truncating it and leaving a partial
// plaintext behind.
//
// Both the current container version and the original version 1 layout are
// accepted.
func DecryptFile(inPath, outPath string, password []byte) error {
	inFile, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer inFile.Close()

	if sameFile(inPath, outPath) {
		return errors.New("refusing to decrypt a file onto itself")
	}

	c, err := ParseHeader(inFile)
	if err != nil {
		return err
	}

	key, err := DeriveKey(password, c.Salt, c.KDF)
	if err != nil {
		return err
	}
	defer zeroize(key)

	aead, err := newAEAD(key)
	if err != nil {
		return err
	}

	cipherBuf := make([]byte, c.ChunkSize+aead.Overhead())
	var aad []byte
	nonce := make([]byte, aead.NonceSize())

	return atomicWrite(outPath, func(w io.Writer) error {
		var written uint64

		for seq := uint32(0); seq < c.MaxChunks(); seq++ {
			n, rerr := io.ReadFull(inFile, cipherBuf)
			if rerr != nil && rerr != io.EOF && rerr != io.ErrUnexpectedEOF {
				return rerr
			}

			// Clean end of stream exactly on a chunk boundary. For v2 the
			// authenticated length in the header is what proves the file is
			// whole, so a short count here is truncation.
			if rerr == io.EOF {
				if seq == 0 {
					return ErrDecryption // header survived, body is gone
				}
				if !c.legacy && written != c.PlaintextSize {
					return ErrDecryption
				}
				// v1 has no recorded length, so a boundary truncation of a v1
				// file cannot be detected. New files are unaffected.
				return nil
			}

			// Version 1 derived the end-of-file marker from the read result,
			// which is why an exact multiple of the chunk size had a trailing
			// empty chunk. Keep that behaviour so old files still decrypt.
			isLast := rerr != nil
			if !c.legacy {
				isLast = c.LastChunk(seq)
			}

			copy(nonce, c.Nonce(seq))
			aad = c.AAD(aad[:0], seq, isLast)

			plaintext, err := aead.Open(nil, nonce, cipherBuf[:n], aad)
			if err != nil {
				return ErrDecryption
			}

			written += uint64(len(plaintext))
			if !c.legacy && written > c.PlaintextSize {
				return ErrDecryption
			}

			if _, err := w.Write(plaintext); err != nil {
				return err
			}
			if isLast {
				if !c.legacy && written != c.PlaintextSize {
					return ErrDecryption
				}
				// Reaching the recorded length is not proof the container ends
				// here; bytes appended after the final chunk must be rejected.
				return requireEOF(inFile)
			}
		}
		return ErrFileTooLarge
	})
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// sameFile reports whether two paths resolve to the same file, following
// symlinks so that decrypting ./x.enc cannot quietly clobber ./x.
func sameFile(a, b string) bool {
	fa, err := os.Stat(a)
	if err != nil {
		return false
	}
	fb, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(fa, fb)
}

// atomicWrite runs fn against a temporary file in the destination directory and
// renames it over dst only after fn returns nil.
//
// The temporary file lives in the same directory as dst so the rename stays on
// one filesystem and is therefore atomic. On any error the temporary file is
// removed and dst is never touched. This is what stops a failed decryption from
// destroying the plaintext that was already sitting at dst.
func atomicWrite(dst string, fn func(io.Writer) error) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".zensec-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	closed := false

	defer func() {
		if !closed {
			_ = tmp.Close()
		}
		if err != nil {
			_ = os.Remove(tmpName)
		}
	}()

	// CreateTemp uses 0600 already, but be explicit: the destination is
	// sensitive and this must not depend on that implementation detail.
	if err = tmp.Chmod(filePerm); err != nil {
		return err
	}
	if err = fn(tmp); err != nil {
		return err
	}
	// Surface write errors that only appear at close or fsync time (full disk,
	// failing network mount) instead of reporting success.
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	closed = true

	if err = os.Rename(tmpName, dst); err != nil {
		return err
	}
	return nil
}
