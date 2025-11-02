const std = @import("std");
const des = @import("des.zig");

test "DES ECB variable plaintext" {
    // NIST SP 800-20 Variable Plaintext Known Answer Tests
    // Fixed key, varying plaintext bits
    const key = [8]u8{ 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };

    const test_vectors = [_][2][8]u8{
        // [plaintext, ciphertext]
        .{
            .{ 0x95, 0xF8, 0xA5, 0xE5, 0xDD, 0x31, 0xD9, 0x00 },
            .{ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        },
        .{
            .{ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
            .{ 0x95, 0xF8, 0xA5, 0xE5, 0xDD, 0x31, 0xD9, 0x00 },
        },
        .{
            .{ 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
            .{ 0xDD, 0x7F, 0x12, 0x1C, 0xA5, 0x01, 0x56, 0x19 },
        },
        .{
            .{ 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
            .{ 0x2E, 0x86, 0x53, 0x10, 0x4F, 0x38, 0x34, 0xEA },
        },
        .{
            .{ 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
            .{ 0x4B, 0xD3, 0x88, 0xFF, 0x6C, 0xD8, 0x1D, 0x4F },
        },
    };

    var subkeys: [16]u64 = undefined;
    des.keySetup(&key, &subkeys, .encrypt);

    for (test_vectors, 0..) |vec, idx| {
        const plaintext = vec[0];
        const expected = vec[1];
        var ciphertext: [8]u8 = undefined;
        des.crypt(&plaintext, &ciphertext, &subkeys);
        try std.testing.expectEqualSlices(u8, &expected, &ciphertext);
        _ = idx; // Variable plaintext test
    }
}

test "DES ECB variable key" {
    // NIST SP 800-20 Variable Key Known Answer Tests
    // Fixed plaintext, varying key bits
    const plaintext = [8]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    const test_vectors = [_][2][8]u8{
        // [key, ciphertext]
        .{
            .{ 0x80, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 },
            .{ 0x95, 0xA8, 0xD7, 0x28, 0x13, 0xDA, 0xA9, 0x4D },
        },
        .{
            .{ 0x40, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 },
            .{ 0x0E, 0xEC, 0x14, 0x87, 0xDD, 0x8C, 0x26, 0xD5 },
        },
        .{
            .{ 0x20, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 },
            .{ 0x7A, 0xD1, 0x6F, 0xFB, 0x79, 0xC4, 0x59, 0x26 },
        },
        .{
            .{ 0x10, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 },
            .{ 0xD3, 0x74, 0x62, 0x94, 0xCA, 0x6A, 0x6C, 0xF3 },
        },
        .{
            .{ 0x08, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 },
            .{ 0x80, 0x9F, 0x5F, 0x87, 0x3C, 0x1F, 0xD7, 0x61 },
        },
    };

    for (test_vectors, 0..) |vec, idx| {
        const key = vec[0];
        const expected = vec[1];
        var subkeys: [16]u64 = undefined;
        des.keySetup(&key, &subkeys, .encrypt);

        var ciphertext: [8]u8 = undefined;
        des.crypt(&plaintext, &ciphertext, &subkeys);

        try std.testing.expectEqualSlices(u8, &expected, &ciphertext);
        _ = idx; // Variable key test
    }
}

test "DES ECB NIST vectors" {
    // Test 1: NIST SP 800-20 Known Answer Test
    {
        const key = [8]u8{ 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };
        const plaintext = [8]u8{ 0x95, 0xF8, 0xA5, 0xE5, 0xDD, 0x31, 0xD9, 0x00 };
        const expected = [8]u8{ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

        var subkeys: [16]u64 = undefined;
        des.keySetup(&key, &subkeys, .encrypt);

        var ciphertext: [8]u8 = undefined;
        des.crypt(&plaintext, &ciphertext, &subkeys);

        try std.testing.expectEqualSlices(u8, &expected, &ciphertext);
    }

    // Test 2: NIST Vector 2
    {
        const key = [8]u8{ 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };
        const plaintext = [8]u8{ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        const expected = [8]u8{ 0x95, 0xF8, 0xA5, 0xE5, 0xDD, 0x31, 0xD9, 0x00 };

        var subkeys: [16]u64 = undefined;
        des.keySetup(&key, &subkeys, .encrypt);

        var ciphertext: [8]u8 = undefined;
        des.crypt(&plaintext, &ciphertext, &subkeys);

        try std.testing.expectEqualSlices(u8, &expected, &ciphertext);
    }

    // Test 3: All Zeros
    {
        const key = [8]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        const plaintext = [8]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        const expected = [8]u8{ 0x8C, 0xA6, 0x4D, 0xE9, 0xC1, 0xB1, 0x23, 0xA7 };

        var subkeys: [16]u64 = undefined;
        des.keySetup(&key, &subkeys, .encrypt);

        var ciphertext: [8]u8 = undefined;
        des.crypt(&plaintext, &ciphertext, &subkeys);

        try std.testing.expectEqualSlices(u8, &expected, &ciphertext);
    }
}

test "DES decrypt" {
    const key = [8]u8{ 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };
    const ciphertext = [8]u8{ 0x95, 0xF8, 0xA5, 0xE5, 0xDD, 0x31, 0xD9, 0x00 };
    const expected_plaintext = [8]u8{ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    var subkeys: [16]u64 = undefined;
    des.keySetup(&key, &subkeys, .decrypt);

    var plaintext: [8]u8 = undefined;
    des.crypt(&ciphertext, &plaintext, &subkeys);

    try std.testing.expectEqualSlices(u8, &expected_plaintext, &plaintext);
}

test "PKCS7 padding" {
    const allocator = std.testing.allocator;

    // Test 1: Full block padding
    {
        const data = [8]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
        const padded = try des.pkcs7Pad(allocator, &data, 8);
        defer allocator.free(padded);

        try std.testing.expectEqual(@as(usize, 16), padded.len);
        try std.testing.expectEqual(@as(u8, 8), padded[padded.len - 1]);

        const unpadded = des.pkcs7Unpad(padded);
        try std.testing.expect(unpadded != null);
        try std.testing.expectEqual(@as(usize, data.len), unpadded.?.len);
        try std.testing.expectEqualSlices(u8, &data, unpadded.?);
    }

    // Test 2: Partial padding
    {
        const data = [5]u8{ 0x01, 0x02, 0x03, 0x04, 0x05 };
        const padded = try des.pkcs7Pad(allocator, &data, 8);
        defer allocator.free(padded);

        try std.testing.expectEqual(@as(usize, 8), padded.len);
        try std.testing.expectEqual(@as(u8, 3), padded[padded.len - 1]);

        const unpadded = des.pkcs7Unpad(padded);
        try std.testing.expect(unpadded != null);
        try std.testing.expectEqual(@as(usize, data.len), unpadded.?.len);
    }
}

test "DES CBC NIST vectors" {
    // NIST CAVP CBC Monte Carlo Test - sample vector
    const allocator = std.testing.allocator;

    const key = [8]u8{ 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };
    const iv = [8]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const plaintext = [16]u8{
        0x95, 0xF8, 0xA5, 0xE5, 0xDD, 0x31, 0xD9, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const expected = [16]u8{
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x95, 0xF8, 0xA5, 0xE5, 0xDD, 0x31, 0xD9, 0x00,
    };

    const ciphertext = try allocator.alloc(u8, plaintext.len);
    defer allocator.free(ciphertext);

    des.cbcEncrypt(&plaintext, ciphertext, &key, &iv);

    for (expected, 0..) |exp_byte, i| {
        try std.testing.expectEqual(exp_byte, ciphertext[i]);
    }
}

test "DES CBC mode" {
    const allocator = std.testing.allocator;

    // Test 1: Basic CBC
    {
        const key = [8]u8{ 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };
        const iv = [8]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        const plaintext = [16]u8{
            0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        };

        const ciphertext = try allocator.alloc(u8, plaintext.len);
        defer allocator.free(ciphertext);

        des.cbcEncrypt(&plaintext, ciphertext, &key, &iv);

        // Decrypt and verify
        const decrypted = try allocator.alloc(u8, ciphertext.len);
        defer allocator.free(decrypted);

        des.cbcDecrypt(ciphertext, decrypted, &key, &iv);

        try std.testing.expectEqualSlices(u8, &plaintext, decrypted);
    }

    // Test 2: LCD Fan Key
    {
        const key = [8]u8{ 115, 108, 118, 51, 116, 117, 122, 120 };
        const iv = key; // Same as key

        const plaintext = [24]u8{
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        };

        // Expected output verified against Python pycryptodome
        const expected_ct = [24]u8{
            0xf8, 0x85, 0x9f, 0x15, 0xbc, 0x14, 0xd8, 0x8b,
            0xb5, 0x60, 0x16, 0x45, 0xab, 0x4d, 0x74, 0x01,
            0xd9, 0xa9, 0x1a, 0xe4, 0x17, 0x0d, 0x0d, 0xe0,
        };

        const ciphertext = try allocator.alloc(u8, plaintext.len);
        defer allocator.free(ciphertext);

        des.cbcEncrypt(&plaintext, ciphertext, &key, &iv);

        for (expected_ct, 0..) |exp_byte, i| {
            try std.testing.expectEqual(exp_byte, ciphertext[i]);
        }

        // Decrypt and verify
        const decrypted = try allocator.alloc(u8, ciphertext.len);
        defer allocator.free(decrypted);

        des.cbcDecrypt(ciphertext, decrypted, &key, &iv);

        try std.testing.expectEqualSlices(u8, &plaintext, decrypted);
    }
}
