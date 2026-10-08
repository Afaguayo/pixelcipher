# pixelcipher

[![CI](https://github.com/Afaguayo/pixelcipher/actions/workflows/ci.yml/badge.svg)](https://github.com/Afaguayo/pixelcipher/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/Rust-stable-orange?logo=rust)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A PNG **steganography** tool written in Rust: hide a text message inside
an image's pixel data, optionally encrypted with AES-256-GCM, and pull it
back out later. The cover image looks visually identical — the message
lives in the least significant bits of each pixel's color channels.

## Download

Prebuilt binaries (Linux, macOS Intel/Apple Silicon, Windows `.exe`) are
published on every tagged release:
**[Download the latest release](https://github.com/Afaguayo/pixelcipher/releases/latest)**.

## Why

Classic LSB steganography is one of the oldest "hide data in plain
sight" techniques, and a great way to learn image formats, bit-level
encoding, and authenticated encryption in the same small project. This
is a data-hiding/learning demo, not a tool for evading any security
control.

## How it works

1. **Payload framing** (`src/payload.rs`) — the message (plus, if
   encrypted, a salt and nonce) is packed into a small binary header:
   magic bytes, a flags byte, optional salt/nonce, a length field, then
   the body.
2. **Encryption** (`src/crypto.rs`, optional) — if you pass
   `--passphrase`, the message is encrypted with **AES-256-GCM**, with
   the key derived from your passphrase via **PBKDF2-HMAC-SHA256**
   (100,000 rounds) and a random 16-byte salt. Wrong passphrase ⇒
   decryption fails outright (GCM is authenticated), not garbage output.
3. **Embedding** (`src/stego.rs`) — the framed payload's bits are written
   one per color channel into the image's R, G, and B values (alpha is
   left untouched, so transparency is unaffected). Each channel's value
   changes by at most 1, which is imperceptible to the eye.
4. **Extraction** — reverses the process: read every R/G/B LSB back into
   bytes, parse the header, decrypt if needed.

## Build from source

Requires a stable Rust toolchain.

```bash
cargo build --release
```

## Usage

```bash
# How much can this image hold?
./target/release/pixelcipher capacity --in cover.png

# Embed a plain message
./target/release/pixelcipher embed --in cover.png --out stego.png --message "meet at the old pier, midnight"

# Extract it back out
./target/release/pixelcipher extract --in stego.png
```

```
300x300 image: 270000 bits / 33750 bytes of raw capacity (payload header uses ~9-37 bytes depending on encryption).
Embedded 14 message bytes (23 total with payload header) into cover.png -> stego.png
meet at the old pier, midnight
```

Encrypted round trip:

```bash
./target/release/pixelcipher embed --in cover.png --out secret.png \
  --message "the launch code is 00000" --passphrase "correct-horse-battery-staple"

./target/release/pixelcipher extract --in secret.png --passphrase "correct-horse-battery-staple"
```

A wrong passphrase fails loudly instead of returning garbage, because
AES-GCM authenticates the ciphertext:

```bash
./target/release/pixelcipher extract --in secret.png --passphrase "wrong-guess"
# Error: decryption failed: wrong passphrase or corrupted data
```

### Commands

| Command | Flags |
|---|---|
| `embed` | `--in <png>`, `--out <png>`, `--message <text>`, `--passphrase <text>` (optional) |
| `extract` | `--in <png>`, `--passphrase <text>` (required if the message was encrypted) |
| `capacity` | `--in <png>` — prints how many bytes the image can hold |

## Tests

```bash
cargo test
```

12 tests cover payload framing round trips (plaintext and encrypted,
plus rejecting bad magic / truncated data), the crypto layer (round
trip, wrong-passphrase failure, salt/nonce randomness), and the LSB
layer itself (embed→extract round trip, alpha preservation, capacity
overflow rejection, bit-order correctness).

## Limitations

- **PNG only**, and must stay lossless — re-saving the output through a
  lossy format (JPEG) or most image editors will destroy the embedded
  bits.
- Capacity is roughly `width × height × 3` bits; a small cover image can
  only hold a short message (use `capacity` to check first).
- This hides data from casual inspection, not from statistical
  steganalysis — it's not designed to resist a dedicated adversary
  looking specifically for LSB steganography.

## License

MIT — see [LICENSE](LICENSE).
