# Security Design

This document describes what ZenSec actually does. Where something is a known
limitation it is stated here rather than omitted.

## Cryptographic primitives

| Concern | Choice |
|---|---|
| Symmetric encryption | AES-256-GCM (AEAD, 12-byte nonce, 16-byte tag) |
| Key derivation | Argon2id, `t=3`, `m=64 MiB`, `p=NumCPU` (min 1), 32-byte output |
| Salt | 16 bytes from `crypto/rand`, fresh per file |
| Nonce prefix | 8 bytes from `crypto/rand`, fresh per file |
| Header integrity | `SHA-256(header[0:50])[:4]` |
| Randomness source | `crypto/rand` exclusively |

The Argon2id cost is above the OWASP baseline of 19 MiB / t=2 / p=1. The values
live in the header, so raising the cost later is a format change rather than a
silent break.

## Container format v2

The header is 54 bytes and is **bound into the associated data of every chunk**,
so any change to it invalidates decryption.

```
offset  size  field
[0:4]     4   magic "ZSEC"
[4]       1   container version (2)
[5]       1   KDF identifier (1 = Argon2id)
[6:8]     2   Argon2 time cost
[8:12]    4   Argon2 memory cost, KiB
[12]      1   Argon2 parallelism
[13]      1   header length (54)
[14:30]  16   salt
[30:38]   8   per-file nonce prefix
[38:42]   4   plaintext chunk size
[42:50]   8   total plaintext length
[50:54]   4   SHA-256(header[0:50])[:4]
```

Then one AEAD record per chunk, in order, with no framing: the chunk sizes are
fully determined by the header.

## How each attack is prevented

**Chunk reordering or substitution.** The chunk index goes into the associated
data *and* into the nonce. Moving a chunk to a different slot changes both, so
the tag no longer verifies.

**Truncation.** Two independent mechanisms:

1. The last chunk is marked in the associated data.
2. The total plaintext length is recorded in the header, and the decryptor
   requires the recovered byte count to match exactly.

Mechanism 2 is what makes truncation detectable at a chunk boundary. Mechanism
1 alone is not enough: when the plaintext is an exact multiple of the chunk
size, the final chunk fills the buffer completely and nothing in the read tells
you it was last. An earlier design relied on the read result and was silently
truncatable in exactly that case.

**Appending data.** Reaching the recorded length is not proof that the container
ends there, so the decryptor reads one byte past the final chunk and rejects the
file if anything is there. Without that check a container whose plaintext is an
exact multiple of the chunk size would accept arbitrary appended bytes, which
contradicts the property the format exists to provide. Encryption applies the
same check to its input, which also catches a file that grew between the `stat`
that recorded its length and the read that consumed it.

**Header tampering.** The whole header is associated data, and the length field
is covered by the SHA-256 tag. Editing the salt, the nonce prefix, the chunk
size, the KDF parameters or the recorded length produces `ErrCorruptedHeader`
before any key derivation happens. This is also why "the header is damaged" is
distinguishable from "the password is wrong", which version 1 could not do.

**Nonce reuse.** The nonce is `noncePrefix(8) ‖ chunkIndex(4)`. The prefix is
64 random bits per file rather than the 4 bytes version 1 used, which left only
32 bits and made per-file collisions likely at around 100k files. Chunk indices
are bounded at 2^32, so the largest file is 256 TiB.

**KDF denial of service.** KDF parameters come from an attacker-controlled
header, so they are range-checked before Argon2 runs: `t` in 1..64, `m` in
8 MiB..1 GiB, `p` in 1..64, chunk size in 4 KiB..16 MiB. Without this, a
crafted header with a valid integrity tag could request a 4 GiB allocation on
every decrypt.

**Data loss on failure.** Both directions write through a temporary file in the
destination directory and `rename` it into place only after the last chunk is
written. A wrong password, a tampered file or a full disk leaves the
destination byte-for-byte unchanged. Version 1 truncated the destination first,
so a single wrong password reduced the original file to zero bytes.

## Deliberate trade-offs

**The plaintext length is stored in the header.** This is metadata disclosure:
an observer can tell how large a file is. The alternative is undetectable
truncation, which is strictly worse. 7-Zip and zip make the same trade.

**Key material is zeroized on a best-effort basis.** The Go compiler may elide
stores to a slice that is never read again, so zeroizing narrows the window in
which a key sits in memory but does not close it.

**Keyfile bytes are used verbatim, including a trailing newline.** Silently
trimming would change the key of a file encrypted earlier and turn a recoverable
mistake into permanent data loss. ZenSec warns instead and tells you to create
keyfiles with `printf`.

**File permissions on Windows.** `os.Chmod` on Windows only toggles the
read-only attribute; there are no Unix permission bits. Access there is
governed by ACLs inherited from the destination directory, not by this tool.

## Version 1 compatibility

Version 1 containers are still decrypted, using their original 4-byte nonce
prefix, 8-byte chunk counter, unauthenticated header and hardcoded KDF
parameters. They are never written again.

Known limitation carried over from v1: because v1 recorded no plaintext length
and derived its end-of-file marker from the read result, truncating a **v1**
file exactly at a chunk boundary is not detected. Reordering, body tampering and
mid-chunk truncation of v1 files are all still detected. Newly created files
are unaffected.

## Out of scope

ZenSec does not hide file sizes, does not resist a local administrator who can
read process memory, does not provide forward secrecy, and cannot revoke a
leaked key. A leaked keyfile is equivalent to leaking the password.

## Reporting a vulnerability

Do **not** open a public issue. Use GitHub Security Advisory to report privately.
