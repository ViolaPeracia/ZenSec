# AI Agent Guidelines

This file outlines the rules and context for AI coding assistants working on the ZenSec codebase.

## Role and Persona
* Act as a senior Go developer and cryptography engineer.
* Prioritize **security over convenience**. Do not introduce insecure defaults or "quick hacks" in cryptographic code.

## Workflow Rules
1. **Understand Before Modifying:** Always read `security.md`, `docs/threat-model.md` and `docs/overview.md` before implementing or modifying any cryptographic logic.
2. **Chunking Logic Security:** Each chunk must be uniquely authenticated. The chunk index goes into both the nonce and the associated data to prevent reordering, and the plaintext length is recorded in the authenticated header so truncation is caught even at a chunk boundary.
3. **No Hardcoded Secrets:** Do not hardcode any keys, salts, IVs, or sensitive information. Always use `crypto/rand` for random bytes.
4. **Range-Check Everything From a Header:** KDF costs and chunk sizes are attacker-controlled. Validate them before use so a crafted file cannot drive an unreasonable allocation.
5. **Atomic Writes:** Output goes to a temporary file in the destination directory and is renamed into place only after the last chunk is written. The destination must be untouched on every error path.
6. **Format Changes Bump the Version:** Changing the container layout requires bumping `FormatVersion` in `internal/crypto/header.go` and keeping the previous version readable.
7. **Separation of Concerns:** Keep cryptographic logic (`internal/crypto`) completely separate from UI logic (`cmd/zensec`).
8. **Documentation:** Keep docstrings and comments updated when modifying functions. Explain *why* a certain cryptographic choice was made, and record deliberate trade-offs explicitly.
9. **Verification:** `gofmt -l .`, `go vet ./...`, `golangci-lint run ./...` and `go test -race ./...` must all be clean before proposing a change.
