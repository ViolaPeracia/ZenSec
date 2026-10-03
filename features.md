# ZenSec Features Detail

## 🔐 Core Cryptographic Primitives
* **AES-256-GCM (Galois/Counter Mode):** Authenticated encryption. Confidentiality plus integrity: any modification causes decryption to fail rather than return altered data.
* **Argon2id Key Derivation:** Memory-hard KDF at `t=3`, `m=64 MiB`, `p=NumCPU`, deriving a 32-byte key. Above the OWASP baseline (19 MiB, t=2, p=1). Parameters are stored per file in the header, so the cost can be raised later without orphaning existing files.

## 🛡️ Attack Mitigations
* **Memory-Efficient Chunking (64 KiB):** Files are processed in fixed-size blocks with a constant working buffer, so a 50 GB file does not need 50 GB of RAM.
* **Chunk Reordering Protection:** each chunk's index is bound into both the GCM nonce and the associated data. Swapping chunk 1 with chunk 5 changes both, so the authentication tag fails.
* **Truncation Protection:** two independent mechanisms. The final chunk is flagged in the associated data, *and* the total plaintext length is recorded in the authenticated header. The second is what catches truncation at a chunk boundary, where a read-based end-of-file marker cannot tell a full final chunk from a partial one.
* **Header Authentication:** the entire header is associated data and carries a SHA-256 tag. Tampering with the salt, nonce prefix, chunk size, KDF costs or recorded length yields a distinct `ErrCorruptedHeader` before any key derivation, so "this file is damaged" is distinguishable from "this password is wrong".
* **Wide Nonce Space:** the per-file nonce prefix is 8 bytes (64 bits), not the 4 bytes the original format used, which left only 32 bits and made collisions likely at around 100k files.
* **Parameter Range Checks:** KDF costs and chunk sizes read from a header are validated before use, so a crafted file cannot request a multi-gigabyte allocation and exhaust memory.
* **Atomic Output:** both directions write to a temporary file in the destination directory and rename into place only after the last chunk is written. A wrong password or tampered input leaves the destination unchanged.
* **No Silent Tail Data:** reaching the recorded plaintext length is not proof the container ends there, so the decryptor checks for a byte past the final chunk and rejects the file if one exists. Encryption applies the same check to its input, which also catches a file that grew mid-encryption instead of truncating it silently.

## 💻 Interface & Automation
* **Minimal CLI:** built on the Go standard library `flag` package. Module dependencies are `golang.org/x/crypto` and `golang.org/x/term`, both under `golang.org/x`.
* **Secure Prompts:** `golang.org/x/term` reads passwords from the terminal descriptor without echoing, keeping them out of the shell history and off screen.
* **Keyfile Support:** any file up to 1 MiB can stand in for a password. Bytes are used verbatim, including a trailing newline, because silently trimming would change the key of a file encrypted earlier. A warning is printed when a keyfile ends in whitespace.
* **Automation Flags:** `-yes` suppresses overwrite prompts and `-out PATH` sets an explicit destination.
* **OS Integrations:**
  - Windows Context Menu via `install_context_menu.reg`.
  - Multi-file batch processing via `batch_zensec.bat` and `batch_zensec.sh`, both of which count failures and exit non-zero.
