const std = @import("std");

pub const DES_BLOCK_SIZE = 8;

pub const Mode = enum {
    encrypt,
    decrypt,
};

// Permutation tables from Go's crypto/des (0-based bit numbering, bit 0 = MSB)
const initial_permutation = [64]u8{
    6,  14, 22, 30, 38, 46, 54, 62,
    4,  12, 20, 28, 36, 44, 52, 60,
    2,  10, 18, 26, 34, 42, 50, 58,
    0,  8,  16, 24, 32, 40, 48, 56,
    7,  15, 23, 31, 39, 47, 55, 63,
    5,  13, 21, 29, 37, 45, 53, 61,
    3,  11, 19, 27, 35, 43, 51, 59,
    1,  9,  17, 25, 33, 41, 49, 57,
};

const final_permutation = [64]u8{
    24, 56, 16, 48, 8,  40, 0,  32,
    25, 57, 17, 49, 9,  41, 1,  33,
    26, 58, 18, 50, 10, 42, 2,  34,
    27, 59, 19, 51, 11, 43, 3,  35,
    28, 60, 20, 52, 12, 44, 4,  36,
    29, 61, 21, 53, 13, 45, 5,  37,
    30, 62, 22, 54, 14, 46, 6,  38,
    31, 63, 23, 55, 15, 47, 7,  39,
};

const expansion_function = [48]u8{
    0,  31, 30, 29, 28, 27, 28, 27,
    26, 25, 24, 23, 24, 23, 22, 21,
    20, 19, 20, 19, 18, 17, 16, 15,
    16, 15, 14, 13, 12, 11, 12, 11,
    10, 9,  8,  7,  8,  7,  6,  5,
    4,  3,  4,  3,  2,  1,  0,  31,
};

const permutation_function = [32]u8{
    16, 25, 12, 11, 3,  20, 4,  15,
    31, 17, 9,  6,  27, 14, 1,  22,
    30, 24, 8,  18, 0,  5,  29, 23,
    13, 19, 2,  26, 10, 21, 28, 7,
};

const permuted_choice1 = [56]u8{
    7,  15, 23, 31, 39, 47, 55, 63,
    6,  14, 22, 30, 38, 46, 54, 62,
    5,  13, 21, 29, 37, 45, 53, 61,
    4,  12, 20, 28, 1,  9,  17, 25,
    33, 41, 49, 57, 2,  10, 18, 26,
    34, 42, 50, 58, 3,  11, 19, 27,
    35, 43, 51, 59, 36, 44, 52, 60,
};

const permuted_choice2 = [48]u8{
    42, 39, 45, 32, 55, 51, 53, 28,
    41, 50, 35, 46, 33, 37, 44, 52,
    30, 48, 40, 49, 29, 36, 43, 54,
    15, 4,  25, 19, 9,  1,  26, 16,
    5,  11, 23, 8,  12, 7,  17, 0,
    22, 3,  10, 14, 6,  20, 27, 24,
};

const s_boxes = [8][4][16]u8{
    .{
        .{ 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
        .{ 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
        .{ 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
        .{ 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 },
    },
    .{
        .{ 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
        .{ 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
        .{ 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
        .{ 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 },
    },
    .{
        .{ 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
        .{ 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
        .{ 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
        .{ 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 },
    },
    .{
        .{ 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
        .{ 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
        .{ 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
        .{ 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 },
    },
    .{
        .{ 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
        .{ 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
        .{ 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
        .{ 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 },
    },
    .{
        .{ 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
        .{ 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
        .{ 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
        .{ 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 },
    },
    .{
        .{ 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
        .{ 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
        .{ 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
        .{ 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 },
    },
    .{
        .{ 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
        .{ 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
        .{ 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
        .{ 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 },
    },
};

const ks_rotations = [16]u8{ 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

// General permutation function
fn permuteBlock(src: u64, permutation: []const u8) u64 {
    var block: u64 = 0;
    const perm_len = permutation.len;
    for (permutation, 0..) |n, idx| {
        const bit = (src >> @intCast(n)) & 1;
        const shift = @as(u6, @intCast(perm_len - 1 - idx));
        block |= bit << shift;
    }
    return block;
}

// Key schedule
pub fn keySetup(key: []const u8, subkeys: *[16]u64, mode: Mode) void {
    // Convert key bytes to u64 (big-endian)
    var k: u64 = 0;
    for (0..8) |i| {
        k = (k << 8) | @as(u64, key[i]);
    }

    // Apply PC-1
    const permuted = permuteBlock(k, &permuted_choice1);

    // Split into C and D (28 bits each)
    var c: u32 = @intCast(permuted >> 28);
    var d: u32 = @intCast(permuted & 0x0FFFFFFF);

    // Generate 16 subkeys
    for (0..16) |round| {
        // Rotate
        const shift = ks_rotations[round];
        c = ((c << @intCast(shift)) | (c >> @intCast(28 - shift))) & 0x0FFFFFFF;
        d = ((d << @intCast(shift)) | (d >> @intCast(28 - shift))) & 0x0FFFFFFF;

        // Combine C and D
        const cd = (@as(u64, c) << 28) | @as(u64, d);

        // Apply PC-2
        const idx = if (mode == .decrypt) 15 - round else round;
        subkeys[idx] = permuteBlock(cd, &permuted_choice2);
    }
}

// DES round function (Feistel)
fn feistel(right: u32, subkey: u64) u32 {
    // Expand right from 32 to 48 bits
    const expanded = permuteBlock(@as(u64, right), &expansion_function);

    // XOR with subkey
    const temp = expanded ^ subkey;

    // S-box substitution (48 bits -> 32 bits)
    var output: u32 = 0;

    for (0..8) |i| {
        // Extract 6 bits for this S-box (from left to right)
        const shift: u6 = @intCast(42 - (i * 6));
        const six_bits: u8 = @intCast((temp >> shift) & 0x3F);

        // Row = bits 0 and 5, Column = bits 1-4
        const row = ((six_bits >> 4) & 0x02) | (six_bits & 0x01);
        const col = (six_bits >> 1) & 0x0F;

        // Lookup in S-box
        const s_output = s_boxes[i][row][col];

        // Place in output (4 bits at a time, from left to right)
        const out_shift: u5 = @intCast(28 - (i * 4));
        output |= @as(u32, s_output) << out_shift;
    }

    // Apply permutation
    const result = permuteBlock(@as(u64, output), &permutation_function);
    return @intCast(result);
}

// DES encryption/decryption of single block
pub fn crypt(input: []const u8, output: []u8, subkeys: *const [16]u64) void {
    // Convert input to u64 (big-endian)
    var block: u64 = 0;
    for (0..8) |i| {
        block = (block << 8) | @as(u64, input[i]);
    }

    // Initial permutation
    block = permuteBlock(block, &initial_permutation);

    // Split into left and right
    var left: u32 = @intCast(block >> 32);
    var right: u32 = @intCast(block & 0xFFFFFFFF);

    // 16 rounds
    for (0..16) |round| {
        const new_right = left ^ feistel(right, subkeys[round]);
        left = right;
        right = new_right;
    }

    // Combine (note: left and right are swapped after 16 rounds)
    const preoutput = (@as(u64, right) << 32) | @as(u64, left);

    // Final permutation
    const result = permuteBlock(preoutput, &final_permutation);

    // Convert back to bytes (big-endian)
    var i: i32 = 7;
    while (i >= 0) : (i -= 1) {
        const idx: usize = @intCast(i);
        output[7 - idx] = @intCast((result >> @intCast(idx * 8)) & 0xFF);
    }
}

// CBC mode encryption
pub fn cbcEncrypt(plaintext: []const u8, ciphertext: []u8, key: []const u8, iv: []const u8) void {
    var subkeys: [16]u64 = undefined;
    keySetup(key, &subkeys, .encrypt);

    var prev_block: [DES_BLOCK_SIZE]u8 = undefined;
    @memcpy(&prev_block, iv);

    const num_blocks = plaintext.len / DES_BLOCK_SIZE;

    for (0..num_blocks) |block_idx| {
        const input_offset = block_idx * DES_BLOCK_SIZE;
        const output_offset = block_idx * DES_BLOCK_SIZE;

        // XOR with previous ciphertext block (or IV)
        var xored: [DES_BLOCK_SIZE]u8 = undefined;
        for (0..DES_BLOCK_SIZE) |i| {
            xored[i] = plaintext[input_offset + i] ^ prev_block[i];
        }

        // Encrypt
        crypt(&xored, ciphertext[output_offset .. output_offset + DES_BLOCK_SIZE], &subkeys);

        // Save ciphertext for next round
        @memcpy(&prev_block, ciphertext[output_offset .. output_offset + DES_BLOCK_SIZE]);
    }
}

// CBC mode decryption
pub fn cbcDecrypt(ciphertext: []const u8, plaintext: []u8, key: []const u8, iv: []const u8) void {
    var subkeys: [16]u64 = undefined;
    keySetup(key, &subkeys, .decrypt);

    var prev_block: [DES_BLOCK_SIZE]u8 = undefined;
    @memcpy(&prev_block, iv);

    const num_blocks = ciphertext.len / DES_BLOCK_SIZE;

    for (0..num_blocks) |block_idx| {
        const input_offset = block_idx * DES_BLOCK_SIZE;
        const output_offset = block_idx * DES_BLOCK_SIZE;

        // Save current ciphertext block before decryption
        var current_block: [DES_BLOCK_SIZE]u8 = undefined;
        @memcpy(&current_block, ciphertext[input_offset .. input_offset + DES_BLOCK_SIZE]);

        // Decrypt
        var temp: [DES_BLOCK_SIZE]u8 = undefined;
        crypt(ciphertext[input_offset .. input_offset + DES_BLOCK_SIZE], &temp, &subkeys);

        // XOR with previous ciphertext block (or IV)
        for (0..DES_BLOCK_SIZE) |i| {
            plaintext[output_offset + i] = temp[i] ^ prev_block[i];
        }

        // Update previous block
        @memcpy(&prev_block, &current_block);
    }
}

// PKCS7 padding
pub fn pkcs7Pad(allocator: std.mem.Allocator, data: []const u8, block_size: usize) ![]u8 {
    var padding_len = block_size - (data.len % block_size);
    if (padding_len == 0) {
        padding_len = block_size;
    }

    const padded = try allocator.alloc(u8, data.len + padding_len);
    @memcpy(padded[0..data.len], data);

    for (data.len..padded.len) |i| {
        padded[i] = @intCast(padding_len);
    }

    return padded;
}

// PKCS7 unpadding
pub fn pkcs7Unpad(data: []const u8) ?[]const u8 {
    if (data.len == 0) {
        return null;
    }

    const padding_len: usize = @intCast(data[data.len - 1]);

    if (padding_len == 0 or padding_len > data.len) {
        return null;
    }

    for (data.len - padding_len..data.len) |i| {
        if (data[i] != @as(u8, @intCast(padding_len))) {
            return null;
        }
    }

    return data[0 .. data.len - padding_len];
}

test "basic" {
    const key = [8]u8{ 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };
    const plaintext = [8]u8{ 0x95, 0xF8, 0xA5, 0xE5, 0xDD, 0x31, 0xD9, 0x00 };
    const expected = [8]u8{ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    var subkeys: [16]u64 = undefined;
    keySetup(&key, &subkeys, .encrypt);

    var ciphertext: [8]u8 = undefined;
    crypt(&plaintext, &ciphertext, &subkeys);

    try std.testing.expectEqualSlices(u8, &expected, &ciphertext);
}
