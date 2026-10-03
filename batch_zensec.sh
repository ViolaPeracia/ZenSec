#!/usr/bin/env bash
# ===============================
# ZenSec Batch Processor (Bash)
# ===============================
# Requires bash 3.2+ (macOS ships 3.2). No mapfile/readarray.

set -euo pipefail

# Allow an explicit binary, e.g. ZENSEC_BIN=./zensec ./batch_zensec.sh
ZENSEC_BIN="${ZENSEC_BIN:-zensec}"

echo "==============================="
echo " ZenSec Batch Processor"
echo "==============================="
echo ""

# Check the binary before asking anything: a missing binary is not the user's fault,
# so report it together with the install hint instead of after 3 prompts.
if ! command -v "$ZENSEC_BIN" >/dev/null 2>&1; then
    echo "ERROR: '$ZENSEC_BIN' not found in PATH."
    echo "       Build it first:  go build -o zensec ."
    echo "       Or point at it:   ZENSEC_BIN=/full/path/to/zensec $0"
    exit 1
fi

if ! read -r -p "Enter the full path to the folder to process: " folder; then
    echo ""
    echo "No input. Aborted."
    exit 1
fi
if [ ! -d "$folder" ] || [ ! -r "$folder" ]; then
    echo "ERROR: '$folder' is not a readable directory."
    exit 1
fi

if ! read -r -p "Enter the full path to your keyfile: " keyfile; then
    echo ""
    echo "No input. Aborted."
    exit 1
fi
if [ ! -f "$keyfile" ] || [ ! -r "$keyfile" ]; then
    echo "ERROR: '$keyfile' is not a readable file."
    exit 1
fi

if ! read -r -p "Do you want to Encrypt (E) or Decrypt (D)? [E/D]: " mode; then
    echo ""
    echo "No input. Aborted."
    exit 1
fi
case "$mode" in
    E|e) action=encrypt ;;
    D|d) action=decrypt ;;
    *)
        echo "ERROR: invalid choice '$mode'. Expected E or D."
        exit 1
        ;;
esac

# Canonical keyfile path so it can be compared against the paths find() reports.
keyfile_abs="$(cd "$(dirname "$keyfile")" && pwd -P)/$(basename "$keyfile")"

ok=0
fail=0
skipped=0

if [ "$action" = encrypt ]; then
    echo ""
    echo "Starting ENCRYPTION process..."
    # -print0 / read -d '' so spaces, quotes, newlines and unicode survive intact.
    # Process substitution (not a pipe) keeps the loop in this shell, so the
    # counters below actually survive - a `find | while` pipeline would not.
    while IFS= read -r -d '' file; do
        if [ "$file" = "$keyfile_abs" ]; then
            echo "Skipping keyfile inside the processed folder: $file"
            skipped=$((skipped + 1))
            continue
        fi
        echo "Encrypting: $file"
        # -yes: the CLI's overwrite prompt reads stdin, which would hang forever
        # in a batch loop. Per-file failures are counted, not fatal.
        if "$ZENSEC_BIN" -encrypt -file "$file" -keyfile "$keyfile_abs" -yes; then
            ok=$((ok + 1))
        else
            echo "   FAILED to encrypt: $file"
            fail=$((fail + 1))
        fi
    done < <(find "$folder" -type f ! -name '*.enc' -print0)
else
    echo ""
    echo "Starting DECRYPTION process..."
    while IFS= read -r -d '' file; do
        if [ "$file" = "$keyfile_abs" ]; then
            echo "Skipping keyfile inside the processed folder: $file"
            skipped=$((skipped + 1))
            continue
        fi
        echo "Decrypting: $file"
        if "$ZENSEC_BIN" -decrypt -file "$file" -keyfile "$keyfile_abs" -yes; then
            ok=$((ok + 1))
        else
            echo "   FAILED to decrypt: $file"
            fail=$((fail + 1))
        fi
    done < <(find "$folder" -type f -name '*.enc' -print0)
fi

total=$((ok + fail))

echo ""
echo "==============================="
echo " Summary"
echo "==============================="
echo " Processed: $total"
echo " Succeeded: $ok"
echo " Failed:   $fail"
if [ "$skipped" -gt 0 ]; then
    echo " Skipped:  $skipped (keyfile inside folder)"
fi

# Make the exit status meaningful: callers can detect partial failures.
if [ "$fail" -gt 0 ]; then
    echo ""
    echo "Process complete WITH ERRORS."
    exit 1
fi

echo ""
echo "Process complete."