# Threat Model

Scope: the ZenSec command-line tool, the container format it reads and writes,
and the shell/registry scripts shipped alongside it. Written for the maintainer
reviewing a change, not for marketing.

## Assets

| Asset | Why it matters |
|---|---|
| Plaintext of an encrypted file | The thing the tool exists to protect |
| Key material (password or keyfile bytes) | Grants full read access to every file it protects |
| Derived AES key | Same, but only for one file |
| Container integrity | If an attacker can make a modified file decrypt "successfully", confidentiality claims collapse |
| The user's original plaintext file at the decrypt destination | Lost data cannot be recovered |

## Assumptions

These are true by construction. If one stops being true, the design is invalid.

1. `crypto/rand` is correctly seeded and not observable by the attacker.
2. AES-GCM and Argon2id as implemented by `golang.org/x/crypto` are sound.
3. The attacker can modify, replace, truncate, reorder or delete ciphertext.
4. The attacker can observe ciphertext headers, including the plaintext length.
5. The attacker can supply a file to the victim and persuade them to decrypt it.
6. The attacker can read the filesystem but not the victim's RAM.
7. The user does not reuse a password they use elsewhere, and does not leave a
   keyfile on a shared drive.

## Trust boundaries

```
  user input                     untrusted
     |  password / keyfile path / file path
     v
  cmd/zensec  ------------------- boundary 1: argument handling
     |  password bytes
     v
  internal/crypto --------------- boundary 2: container parsing (the real attack surface)
     |  parsed header -> KDF params, salt, nonce, sizes
     v
  crypto/rand, argon2, aes-gcm  boundary 3: primitives, trusted
```

Boundary 2 is where every hostile input arrives. Everything the header claims is
attacker input until the integrity tag and the range checks have passed.

## Threats and controls

| # | Threat | Control | Verified by |
|---|---|---|---|
| T1 | Read plaintext without the key | AES-256-GCM, Argon2id, fresh salt and nonce per file | round-trip + wrong-password tests |
| T2 | Weak key from a low-entropy password | Argon2id at 64 MiB / t=3, above OWASP baseline | `TestKDFValidation` |
| T3 | GCM keystream reuse across files | 8-byte nonce prefix, was 4 bytes in v1 | `TestNoncePrefixIsWideEnough` |
| T4 | GCM nonce reuse across chunks | chunk index in the nonce | `TestUniqueNoncePerChunk` |
| T5 | Chunk reordering or substitution | index in nonce and AAD | `TestChunkReorderingIsDetected` |
| T6 | Truncation mid-chunk | end-of-file marker in AAD | `TestTruncationIsDetected` |
| T7 | Truncation at a chunk boundary | authenticated plaintext length in header | `TestBoundaryTruncationIsDetected` |
| T7b | Data appended after the final chunk | read past the last chunk, reject if anything remains | `TestAppendedDataAfterFinalChunkIsRejected` |
| T8 | Header tampering to grief or downgrade | header in AAD + SHA-256 tag | `TestHeaderFieldsAreAuthenticated` |
| T9 | Hostile KDF parameters causing OOM | range check before Argon2 | `TestHostileKDFParamsAreRejected` |
| T10 | Parser crash on malformed input | no panic on any input; fuzz target | `TestMalformedInputNeverPanics`, `FuzzDecryptFile` |
| T11 | Attacker-supplied `.enc` destroys the user's plaintext | atomic write via temp file + rename | `TestFailedDecryptLeavesDestinationUntouched`, `TestWrongKeyfileLeavesFileIntact` |
| T12 | Keyfile confusion from trailing whitespace | bytes used verbatim, explicit warning | `TestLoadKeyfile` |
| T13 | Key material linger in memory | zeroize on use | `TestZeroizeClearsBytes` |
| T14 | Plaintext readable by other local users | `0600` on output (POSIX only) | `TestOutputPermissionsArePrivate` |
| T15 | Supply chain compromise of dependencies | 2 deps, both `golang.org/x/*`; `govulncheck` in CI | `build.yml` |
| T16 | Unverified release binaries | SHA256SUMS + SLSA provenance | `release.yml` |

## Accepted risks

- **A file destroyed outside ZenSec cannot be recovered.** ZenSec is not a
  backup tool. Batch scripts count failures and exit non-zero rather than
  pressing on, but a mid-run power loss can still leave a temp file behind.
- **The plaintext length is public.** See `security.md`.
- **No forward secrecy.** One leaked key opens every file it protected.
- **A local administrator can read the process.** Password entry uses
  `term.ReadPassword` so it never reaches the shell history, but it is in the
  process memory while the tool runs.
- **v1 boundary truncation.** Inherited from the old format and not fixable
  without rewriting those files. See `security.md`.
- **`0666` on Windows.** `Chmod` cannot express `0600` there; ACLs decide.

## Review checklist for changes to `internal/crypto`

`agents.md` requires explicit human review for cryptographic changes. Minimum
questions before merging:

1. Does the change alter the container format? If so, has `version` been bumped
   and can version 1 still be read?
2. Can the change be exploited by a crafted header? If it reads a value from the
   header, is that value range-checked *before* use?
3. Does the change touch nonce construction? Per-file entropy must be at least
   64 bits and the per-chunk component must be provably unique.
4. Does the change touch the atomic write path? Is the destination still
   untouched on every error path?
5. Is there a test that fails before the change and passes after it?
6. `gofmt -l .`, `go vet ./...`, `golangci-lint run ./...` and
   `go test -race ./...` are all clean.
