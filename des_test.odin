package des

import "core:testing"

// NIST SP 800-20 Variable Plaintext Known Answer Tests
@(test)
test_des_ecb_variable_plaintext :: proc(t: ^testing.T) {
	// Fixed key, varying plaintext bits
	key := [8]u8{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01}

	test_vectors := [][2][8]u8{
		// [plaintext, ciphertext]
		{
			{0x95, 0xF8, 0xA5, 0xE5, 0xDD, 0x31, 0xD9, 0x00},
			{0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			{0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			{0x95, 0xF8, 0xA5, 0xE5, 0xDD, 0x31, 0xD9, 0x00},
		},
		{
			{0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			{0xDD, 0x7F, 0x12, 0x1C, 0xA5, 0x01, 0x56, 0x19},
		},
		{
			{0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			{0x2E, 0x86, 0x53, 0x10, 0x4F, 0x38, 0x34, 0xEA},
		},
		{
			{0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			{0x4B, 0xD3, 0x88, 0xFF, 0x6C, 0xD8, 0x1D, 0x4F},
		},
	}

	subkeys: [16]u64
	des_key_setup(key[:], &subkeys, .Encrypt)

	for vec, idx in test_vectors {
		plaintext := vec[0]
		expected := vec[1]
		ciphertext: [8]u8
		des_crypt(plaintext[:], ciphertext[:], &subkeys)
		testing.expectf(
			t,
			ciphertext == expected,
			"Variable plaintext test %d failed",
			idx + 1,
		)
	}
}

// NIST SP 800-20 Variable Key Known Answer Tests
@(test)
test_des_ecb_variable_key :: proc(t: ^testing.T) {
	// Fixed plaintext, varying key bits
	plaintext := [8]u8{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	test_vectors := [][2][8]u8{
		// [key, ciphertext]
		{
			{0x80, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01},
			{0x95, 0xA8, 0xD7, 0x28, 0x13, 0xDA, 0xA9, 0x4D},
		},
		{
			{0x40, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01},
			{0x0E, 0xEC, 0x14, 0x87, 0xDD, 0x8C, 0x26, 0xD5},
		},
		{
			{0x20, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01},
			{0x7A, 0xD1, 0x6F, 0xFB, 0x79, 0xC4, 0x59, 0x26},
		},
		{
			{0x10, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01},
			{0xD3, 0x74, 0x62, 0x94, 0xCA, 0x6A, 0x6C, 0xF3},
		},
		{
			{0x08, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01},
			{0x80, 0x9F, 0x5F, 0x87, 0x3C, 0x1F, 0xD7, 0x61},
		},
	}

	for vec, idx in test_vectors {
		key := vec[0]
		expected := vec[1]
		subkeys: [16]u64
		des_key_setup(key[:], &subkeys, .Encrypt)

		ciphertext: [8]u8
		des_crypt(plaintext[:], ciphertext[:], &subkeys)

		testing.expectf(
			t,
			ciphertext == expected,
			"Variable key test %d failed",
			idx + 1,
		)
	}
}

@(test)
test_des_ecb_nist_vectors :: proc(t: ^testing.T) {
	// Test 1: NIST SP 800-20 Known Answer Test
	{
		key := [8]u8{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01}
		plaintext := [8]u8{0x95, 0xF8, 0xA5, 0xE5, 0xDD, 0x31, 0xD9, 0x00}
		expected := [8]u8{0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

		subkeys: [16]u64
		des_key_setup(key[:], &subkeys, .Encrypt)

		ciphertext: [8]u8
		des_crypt(plaintext[:], ciphertext[:], &subkeys)

		testing.expect(t, ciphertext == expected, "NIST Known Answer Test failed")
	}

	// Test 2: NIST Vector 2
	{
		key := [8]u8{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01}
		plaintext := [8]u8{0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		expected := [8]u8{0x95, 0xF8, 0xA5, 0xE5, 0xDD, 0x31, 0xD9, 0x00}

		subkeys: [16]u64
		des_key_setup(key[:], &subkeys, .Encrypt)

		ciphertext: [8]u8
		des_crypt(plaintext[:], ciphertext[:], &subkeys)

		testing.expect(t, ciphertext == expected, "NIST Vector 2 failed")
	}

	// Test 3: All Zeros
	{
		key := [8]u8{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		plaintext := [8]u8{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		expected := [8]u8{0x8C, 0xA6, 0x4D, 0xE9, 0xC1, 0xB1, 0x23, 0xA7}

		subkeys: [16]u64
		des_key_setup(key[:], &subkeys, .Encrypt)

		ciphertext: [8]u8
		des_crypt(plaintext[:], ciphertext[:], &subkeys)

		testing.expect(t, ciphertext == expected, "All zeros test failed")
	}

}

@(test)
test_des_decrypt :: proc(t: ^testing.T) {
	key := [8]u8{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01}
	ciphertext := [8]u8{0x95, 0xF8, 0xA5, 0xE5, 0xDD, 0x31, 0xD9, 0x00}
	expected_plaintext := [8]u8{0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	subkeys: [16]u64
	des_key_setup(key[:], &subkeys, .Decrypt)

	plaintext: [8]u8
	des_crypt(ciphertext[:], plaintext[:], &subkeys)

	testing.expect(t, plaintext == expected_plaintext, "DES decryption failed")
}

@(test)
test_pkcs7_padding :: proc(t: ^testing.T) {
	// Test 1: Full block padding
	{
		data := [8]u8{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
		padded := pkcs7_pad(data[:], 8)
		defer delete(padded)

		testing.expect(t, len(padded) == 16, "Padded length should be 16")
		testing.expect(t, padded[len(padded) - 1] == 8, "Padding byte should be 8")

		unpadded, ok := pkcs7_unpad(padded)
		testing.expect(t, ok, "Unpadding should succeed")
		testing.expect(t, len(unpadded) == len(data), "Unpadded length should match original")
		for i in 0 ..< len(data) {
			testing.expect(t, unpadded[i] == data[i], "Unpadded data should match original")
		}
	}

	// Test 2: Partial padding
	{
		data := [5]u8{0x01, 0x02, 0x03, 0x04, 0x05}
		padded := pkcs7_pad(data[:], 8)
		defer delete(padded)

		testing.expect(t, len(padded) == 8, "Padded length should be 8")
		testing.expect(t, padded[len(padded) - 1] == 3, "Padding byte should be 3")

		unpadded, ok := pkcs7_unpad(padded)
		testing.expect(t, ok, "Unpadding should succeed")
		testing.expect(t, len(unpadded) == len(data), "Unpadded length should match original")
	}
}

// NIST CBC Mode Test Vectors
@(test)
test_des_cbc_nist_vectors :: proc(t: ^testing.T) {
	// NIST CAVP CBC Monte Carlo Test - sample vector
	{
		key := [8]u8{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01}
		iv := [8]u8{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		plaintext := [16]u8 {
			0x95,
			0xF8,
			0xA5,
			0xE5,
			0xDD,
			0x31,
			0xD9,
			0x00,
			0x00,
			0x00,
			0x00,
			0x00,
			0x00,
			0x00,
			0x00,
			0x00,
		}
		expected := [16]u8 {
			0x80,
			0x00,
			0x00,
			0x00,
			0x00,
			0x00,
			0x00,
			0x00,
			0x95,
			0xF8,
			0xA5,
			0xE5,
			0xDD,
			0x31,
			0xD9,
			0x00,
		}

		ciphertext := make([]u8, len(plaintext))
		defer delete(ciphertext)

		des_cbc_encrypt(plaintext[:], ciphertext, key[:], iv[:])

		for i in 0 ..< len(expected) {
			testing.expectf(
				t,
				ciphertext[i] == expected[i],
				"NIST CBC vector mismatch at byte %d: got 0x%02x, expected 0x%02x",
				i,
				ciphertext[i],
				expected[i],
			)
		}
	}

}

@(test)
test_des_cbc_mode :: proc(t: ^testing.T) {
	// Test 1: Basic CBC
	{
		key := [8]u8{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01}
		iv := [8]u8{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		plaintext := [16]u8 {
			0x80,
			0x00,
			0x00,
			0x00,
			0x00,
			0x00,
			0x00,
			0x00,
			0x00,
			0x00,
			0x00,
			0x00,
			0x00,
			0x00,
			0x00,
			0x00,
		}

		ciphertext := make([]u8, len(plaintext))
		defer delete(ciphertext)

		des_cbc_encrypt(plaintext[:], ciphertext, key[:], iv[:])

		// Decrypt and verify
		decrypted := make([]u8, len(ciphertext))
		defer delete(decrypted)

		des_cbc_decrypt(ciphertext, decrypted, key[:], iv[:])

		for i in 0 ..< len(plaintext) {
			testing.expect(
				t,
				plaintext[i] == decrypted[i],
				"CBC decryption should match plaintext",
			)
		}
	}

	// Test 2: LCD Fan Key
	{
		key := [8]u8{115, 108, 118, 51, 116, 117, 122, 120}
		iv := key // Same as key

		plaintext := [24]u8 {
			0x00,
			0x01,
			0x02,
			0x03,
			0x04,
			0x05,
			0x06,
			0x07,
			0x08,
			0x09,
			0x0A,
			0x0B,
			0x0C,
			0x0D,
			0x0E,
			0x0F,
			0x10,
			0x11,
			0x12,
			0x13,
			0x14,
			0x15,
			0x16,
			0x17,
		}

		// Expected output verified against Python pycryptodome
		expected_ct := [24]u8 {
			0xf8,
			0x85,
			0x9f,
			0x15,
			0xbc,
			0x14,
			0xd8,
			0x8b,
			0xb5,
			0x60,
			0x16,
			0x45,
			0xab,
			0x4d,
			0x74,
			0x01,
			0xd9,
			0xa9,
			0x1a,
			0xe4,
			0x17,
			0x0d,
			0x0d,
			0xe0,
		}

		ciphertext := make([]u8, len(plaintext))
		defer delete(ciphertext)

		des_cbc_encrypt(plaintext[:], ciphertext, key[:], iv[:])

		for i in 0 ..< len(expected_ct) {
			testing.expectf(
				t,
				ciphertext[i] == expected_ct[i],
				"Ciphertext mismatch at byte %d: got 0x%02x, expected 0x%02x",
				i,
				ciphertext[i],
				expected_ct[i],
			)
		}

		// Decrypt and verify
		decrypted := make([]u8, len(ciphertext))
		defer delete(decrypted)

		des_cbc_decrypt(ciphertext, decrypted, key[:], iv[:])

		for i in 0 ..< len(plaintext) {
			testing.expect(
				t,
				plaintext[i] == decrypted[i],
				"CBC decryption should match plaintext",
			)
		}
	}
}

