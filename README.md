# DES Encryption

A pure Odin implementation of the Data Encryption Standard (DES) cipher, featuring both ECB and CBC modes with PKCS7 padding support.

## Features

- **ECB Mode**: Electronic Codebook mode for single block encryption/decryption
- **CBC Mode**: Cipher Block Chaining mode for secure multi-block encryption
- **PKCS7 Padding**: Automatic padding and unpadding for arbitrary-length data
- **NIST Validated**: Comprehensive test suite using NIST SP 800-20 test vectors
- **Zero Dependencies**: Pure Odin implementation with no external dependencies

## Installation

```bash
git clone https://github.com/chrishayen/des.git
cd des
```

## Usage

### ECB Mode (Single Block)

```odin
package main

import "des"

main :: proc() {
    key := [8]u8{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
    plaintext := [8]u8{0x4E, 0x6F, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74}

    // Setup encryption subkeys
    subkeys: [16]u64
    des.des_key_setup(key[:], &subkeys, .Encrypt)

    // Encrypt
    ciphertext: [8]u8
    des.des_crypt(plaintext[:], ciphertext[:], &subkeys)

    // Setup decryption subkeys
    des.des_key_setup(key[:], &subkeys, .Decrypt)

    // Decrypt
    decrypted: [8]u8
    des.des_crypt(ciphertext[:], decrypted[:], &subkeys)
}
```

### CBC Mode (Multi-Block)

```odin
package main

import "des"

main :: proc() {
    key := [8]u8{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
    iv := [8]u8{0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF}
    plaintext := []u8{0x4E, 0x6F, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74,
                      0x68, 0x65, 0x20, 0x74, 0x69, 0x6D, 0x65, 0x20}

    // Encrypt
    ciphertext := make([]u8, len(plaintext))
    defer delete(ciphertext)
    des.des_cbc_encrypt(plaintext, ciphertext, key[:], iv[:])

    // Decrypt
    decrypted := make([]u8, len(ciphertext))
    defer delete(decrypted)
    des.des_cbc_decrypt(ciphertext, decrypted, key[:], iv[:])
}
```

### PKCS7 Padding

```odin
package main

import "des"

main :: proc() {
    data := []u8{0x01, 0x02, 0x03, 0x04, 0x05}

    // Add padding
    padded := des.pkcs7_pad(data, des.DES_BLOCK_SIZE)
    defer delete(padded)

    // Remove padding
    unpadded, ok := des.pkcs7_unpad(padded)
    if ok {
        // unpadded now contains the original data
    }
}
```

## API Reference

### Constants

- `DES_BLOCK_SIZE :: 8` - DES block size in bytes

### Types

```odin
DES_Mode :: enum {
    Encrypt,
    Decrypt,
}
```

### Functions

#### `des_key_setup`
```odin
des_key_setup :: proc(key: []u8, subkeys: ^[16]u64, mode: DES_Mode)
```
Generates 16 subkeys from an 8-byte DES key for encryption or decryption.

**Parameters:**
- `key`: 8-byte DES key
- `subkeys`: Pointer to array that will hold the 16 generated subkeys
- `mode`: `.Encrypt` or `.Decrypt`

#### `des_crypt`
```odin
des_crypt :: proc(input: []u8, output: []u8, subkeys: ^[16]u64)
```
Encrypts or decrypts a single 8-byte block using DES ECB mode.

**Parameters:**
- `input`: 8-byte input block
- `output`: 8-byte output buffer
- `subkeys`: Pointer to subkeys from `des_key_setup`

#### `des_cbc_encrypt`
```odin
des_cbc_encrypt :: proc(plaintext: []u8, ciphertext: []u8, key: []u8, iv: []u8)
```
Encrypts data using DES in CBC mode.

**Parameters:**
- `plaintext`: Input data (must be multiple of 8 bytes)
- `ciphertext`: Output buffer (same length as plaintext)
- `key`: 8-byte DES key
- `iv`: 8-byte initialization vector

#### `des_cbc_decrypt`
```odin
des_cbc_decrypt :: proc(ciphertext: []u8, plaintext: []u8, key: []u8, iv: []u8)
```
Decrypts data using DES in CBC mode.

**Parameters:**
- `ciphertext`: Encrypted data (must be multiple of 8 bytes)
- `plaintext`: Output buffer (same length as ciphertext)
- `key`: 8-byte DES key
- `iv`: 8-byte initialization vector

#### `pkcs7_pad`
```odin
pkcs7_pad :: proc(data: []u8, block_size: int, allocator := context.allocator) -> []u8
```
Adds PKCS7 padding to data.

**Parameters:**
- `data`: Input data
- `block_size`: Block size for padding (typically 8 for DES)
- `allocator`: Optional custom allocator

**Returns:** Padded data (caller must free)

#### `pkcs7_unpad`
```odin
pkcs7_unpad :: proc(data: []u8) -> ([]u8, bool)
```
Removes PKCS7 padding from data.

**Parameters:**
- `data`: Padded data

**Returns:** `(unpadded_data, success)` where success indicates valid padding

## Testing

The implementation includes comprehensive NIST test vectors:

```bash
odin test .
```

Test coverage includes:
- NIST SP 800-20 Variable Plaintext Known Answer Tests
- NIST SP 800-20 Variable Key Known Answer Tests
- NIST CAVP CBC Mode Tests
- PKCS7 padding validation
- Encryption/decryption roundtrip verification

## Security Notice

DES is considered cryptographically broken and should not be used for new applications. This implementation is provided for:

- Legacy system compatibility
- Educational purposes
- Historical reference
- Protocol implementations requiring DES

For modern applications, use AES or other contemporary ciphers.

## License

MIT License - see LICENSE file for details

## Author

Chris Hayen ([@chrishayen](https://github.com/chrishayen))

## Acknowledgments

- Permutation tables derived from Go's `crypto/des` package
- Test vectors from NIST SP 800-20
