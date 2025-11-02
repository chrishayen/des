# DES Encryption

A pure Zig implementation of the Data Encryption Standard (DES) cipher, featuring both ECB and CBC modes with PKCS7 padding support.

## Features

- **ECB Mode**: Electronic Codebook mode for single block encryption/decryption
- **CBC Mode**: Cipher Block Chaining mode for secure multi-block encryption
- **PKCS7 Padding**: Automatic padding and unpadding for arbitrary-length data
- **NIST Validated**: Comprehensive test suite using NIST SP 800-20 test vectors
- **Zero Dependencies**: Pure Zig implementation with no external dependencies

## Installation

```bash
git clone https://github.com/chrishayen/des.git
cd des
```

## Usage

### ECB Mode (Single Block)

```zig
const std = @import("std");
const des = @import("des.zig");

pub fn main() !void {
    const key = [8]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
    const plaintext = [8]u8{ 0x4E, 0x6F, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74 };

    // Setup encryption subkeys
    var subkeys: [16]u64 = undefined;
    des.keySetup(&key, &subkeys, .encrypt);

    // Encrypt
    var ciphertext: [8]u8 = undefined;
    des.crypt(&plaintext, &ciphertext, &subkeys);

    // Setup decryption subkeys
    des.keySetup(&key, &subkeys, .decrypt);

    // Decrypt
    var decrypted: [8]u8 = undefined;
    des.crypt(&ciphertext, &decrypted, &subkeys);
}
```

### CBC Mode (Multi-Block)

```zig
const std = @import("std");
const des = @import("des.zig");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const key = [8]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
    const iv = [8]u8{ 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF };
    const plaintext = [16]u8{
        0x4E, 0x6F, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74,
        0x68, 0x65, 0x20, 0x74, 0x69, 0x6D, 0x65, 0x20,
    };

    // Encrypt
    const ciphertext = try allocator.alloc(u8, plaintext.len);
    defer allocator.free(ciphertext);
    des.cbcEncrypt(&plaintext, ciphertext, &key, &iv);

    // Decrypt
    const decrypted = try allocator.alloc(u8, ciphertext.len);
    defer allocator.free(decrypted);
    des.cbcDecrypt(ciphertext, decrypted, &key, &iv);
}
```

### PKCS7 Padding

```zig
const std = @import("std");
const des = @import("des.zig");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const data = [5]u8{ 0x01, 0x02, 0x03, 0x04, 0x05 };

    // Add padding
    const padded = try des.pkcs7Pad(allocator, &data, des.DES_BLOCK_SIZE);
    defer allocator.free(padded);

    // Remove padding
    if (des.pkcs7Unpad(padded)) |unpadded| {
        // unpadded now contains the original data
        _ = unpadded;
    }
}
```

## API Reference

### Constants

- `DES_BLOCK_SIZE = 8` - DES block size in bytes

### Types

```zig
pub const Mode = enum {
    encrypt,
    decrypt,
};
```

### Functions

#### `keySetup`
```zig
pub fn keySetup(key: []const u8, subkeys: *[16]u64, mode: Mode) void
```
Generates 16 subkeys from an 8-byte DES key for encryption or decryption.

**Parameters:**
- `key`: 8-byte DES key
- `subkeys`: Pointer to array that will hold the 16 generated subkeys
- `mode`: `.encrypt` or `.decrypt`

#### `crypt`
```zig
pub fn crypt(input: []const u8, output: []u8, subkeys: *const [16]u64) void
```
Encrypts or decrypts a single 8-byte block using DES ECB mode.

**Parameters:**
- `input`: 8-byte input block
- `output`: 8-byte output buffer
- `subkeys`: Pointer to subkeys from `keySetup`

#### `cbcEncrypt`
```zig
pub fn cbcEncrypt(plaintext: []const u8, ciphertext: []u8, key: []const u8, iv: []const u8) void
```
Encrypts data using DES in CBC mode.

**Parameters:**
- `plaintext`: Input data (must be multiple of 8 bytes)
- `ciphertext`: Output buffer (same length as plaintext)
- `key`: 8-byte DES key
- `iv`: 8-byte initialization vector

#### `cbcDecrypt`
```zig
pub fn cbcDecrypt(ciphertext: []const u8, plaintext: []u8, key: []const u8, iv: []const u8) void
```
Decrypts data using DES in CBC mode.

**Parameters:**
- `ciphertext`: Encrypted data (must be multiple of 8 bytes)
- `plaintext`: Output buffer (same length as ciphertext)
- `key`: 8-byte DES key
- `iv`: 8-byte initialization vector

#### `pkcs7Pad`
```zig
pub fn pkcs7Pad(allocator: std.mem.Allocator, data: []const u8, block_size: usize) ![]u8
```
Adds PKCS7 padding to data.

**Parameters:**
- `allocator`: Memory allocator
- `data`: Input data
- `block_size`: Block size for padding (typically 8 for DES)

**Returns:** Padded data (caller must free)

#### `pkcs7Unpad`
```zig
pub fn pkcs7Unpad(data: []const u8) ?[]const u8
```
Removes PKCS7 padding from data.

**Parameters:**
- `data`: Padded data

**Returns:** `unpadded_data` or `null` if padding is invalid

## Testing

The implementation includes comprehensive NIST test vectors:

```bash
zig test des_test.zig
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
