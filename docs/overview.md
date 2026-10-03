# ZenSec Project Overview

## What is ZenSec?
ZenSec is a modern, cross-platform file encryption utility designed to bring enterprise-grade security to individual users. Its core philosophy revolves around making strong cryptography accessible, fast, and minimal. We prioritize the UNIX philosophy: do one thing and do it well, avoiding unnecessary abstractions like complex TUIs or GUIs.

## Core Objectives
1.  **Security First:** Use robust, proven cryptographic primitives (AES-256-GCM, Argon2id) and make the design decisions auditable.
2.  **Performance:** Efficiently handle very large files (e.g., video files, backups) using stream processing to prevent out-of-memory errors.
3.  **Simplicity:** Provide a minimal CLI interface that seamlessly integrates with existing OS tools and workflows.

## Architecture Highlights
*   **Crypto Core (`internal/crypto`):** An independent module that handles all encryption/decryption logic securely. Container format, key derivation, atomic file writes and nothing else.
*   **CLI Layer (`cmd/zensec`):** Argument handling, terminal prompts and output. Built on the standard library plus `golang.org/x/term` for hidden password entry.
*   **OS Integration Layer:** Native shell scripts and a registry file to bridge the gap for users who prefer visual interaction (e.g., right-click context menus).

## Dependencies
Two module dependencies, both under `golang.org/x`: `golang.org/x/crypto` (Argon2id) and `golang.org/x/term` (hidden password entry). `golang.org/x/sys` is pulled in indirectly. CI runs `govulncheck` on every change.
