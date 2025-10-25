package des

DES_BLOCK_SIZE :: 8

DES_Mode :: enum {
	Encrypt,
	Decrypt,
}

// Permutation tables from Go's crypto/des (0-based bit numbering, bit 0 = MSB)
initial_permutation := [64]u8 {
	6,
	14,
	22,
	30,
	38,
	46,
	54,
	62,
	4,
	12,
	20,
	28,
	36,
	44,
	52,
	60,
	2,
	10,
	18,
	26,
	34,
	42,
	50,
	58,
	0,
	8,
	16,
	24,
	32,
	40,
	48,
	56,
	7,
	15,
	23,
	31,
	39,
	47,
	55,
	63,
	5,
	13,
	21,
	29,
	37,
	45,
	53,
	61,
	3,
	11,
	19,
	27,
	35,
	43,
	51,
	59,
	1,
	9,
	17,
	25,
	33,
	41,
	49,
	57,
}

final_permutation := [64]u8 {
	24,
	56,
	16,
	48,
	8,
	40,
	0,
	32,
	25,
	57,
	17,
	49,
	9,
	41,
	1,
	33,
	26,
	58,
	18,
	50,
	10,
	42,
	2,
	34,
	27,
	59,
	19,
	51,
	11,
	43,
	3,
	35,
	28,
	60,
	20,
	52,
	12,
	44,
	4,
	36,
	29,
	61,
	21,
	53,
	13,
	45,
	5,
	37,
	30,
	62,
	22,
	54,
	14,
	46,
	6,
	38,
	31,
	63,
	23,
	55,
	15,
	47,
	7,
	39,
}

expansion_function := [48]u8 {
	0,
	31,
	30,
	29,
	28,
	27,
	28,
	27,
	26,
	25,
	24,
	23,
	24,
	23,
	22,
	21,
	20,
	19,
	20,
	19,
	18,
	17,
	16,
	15,
	16,
	15,
	14,
	13,
	12,
	11,
	12,
	11,
	10,
	9,
	8,
	7,
	8,
	7,
	6,
	5,
	4,
	3,
	4,
	3,
	2,
	1,
	0,
	31,
}

permutation_function := [32]u8 {
	16,
	25,
	12,
	11,
	3,
	20,
	4,
	15,
	31,
	17,
	9,
	6,
	27,
	14,
	1,
	22,
	30,
	24,
	8,
	18,
	0,
	5,
	29,
	23,
	13,
	19,
	2,
	26,
	10,
	21,
	28,
	7,
}

permuted_choice1 := [56]u8 {
	7,
	15,
	23,
	31,
	39,
	47,
	55,
	63,
	6,
	14,
	22,
	30,
	38,
	46,
	54,
	62,
	5,
	13,
	21,
	29,
	37,
	45,
	53,
	61,
	4,
	12,
	20,
	28,
	1,
	9,
	17,
	25,
	33,
	41,
	49,
	57,
	2,
	10,
	18,
	26,
	34,
	42,
	50,
	58,
	3,
	11,
	19,
	27,
	35,
	43,
	51,
	59,
	36,
	44,
	52,
	60,
}

permuted_choice2 := [48]u8 {
	42,
	39,
	45,
	32,
	55,
	51,
	53,
	28,
	41,
	50,
	35,
	46,
	33,
	37,
	44,
	52,
	30,
	48,
	40,
	49,
	29,
	36,
	43,
	54,
	15,
	4,
	25,
	19,
	9,
	1,
	26,
	16,
	5,
	11,
	23,
	8,
	12,
	7,
	17,
	0,
	22,
	3,
	10,
	14,
	6,
	20,
	27,
	24,
}

s_boxes := [8][4][16]u8 {
	{
		{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
		{0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
		{4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
		{15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},
	},
	{
		{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
		{3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
		{0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
		{13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9},
	},
	{
		{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
		{13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
		{13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
		{1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12},
	},
	{
		{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
		{13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
		{10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
		{3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14},
	},
	{
		{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
		{14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
		{4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
		{11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3},
	},
	{
		{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
		{10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
		{9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
		{4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13},
	},
	{
		{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
		{13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
		{1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
		{6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12},
	},
	{
		{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
		{1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
		{7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
		{2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11},
	},
}

ks_rotations := [16]u8{1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1}

// General permutation function
permute_block :: proc(src: u64, permutation: []u8) -> u64 {
	block: u64 = 0
	perm_len := len(permutation)
	for idx in 0 ..< perm_len {
		n := permutation[idx]
		bit := (src >> n) & 1
		block |= bit << uint(perm_len - 1 - idx)
	}
	return block
}

// Key schedule
des_key_setup :: proc(key: []u8, subkeys: ^[16]u64, mode: DES_Mode) {
	// Convert key bytes to u64 (big-endian)
	k: u64 = 0
	for i in 0 ..< 8 {
		k = (k << 8) | u64(key[i])
	}

	// Apply PC-1
	permuted := permute_block(k, permuted_choice1[:])

	// Split into C and D (28 bits each)
	c := u32(permuted >> 28)
	d := u32(permuted & 0x0FFFFFFF)

	// Generate 16 subkeys
	for round in 0 ..< 16 {
		// Rotate
		shift := ks_rotations[round]
		c = ((c << shift) | (c >> (28 - shift))) & 0x0FFFFFFF
		d = ((d << shift) | (d >> (28 - shift))) & 0x0FFFFFFF

		// Combine C and D
		cd := (u64(c) << 28) | u64(d)

		// Apply PC-2
		idx := round
		if mode == .Decrypt {
			idx = 15 - round
		}
		subkeys[idx] = permute_block(cd, permuted_choice2[:])
	}
}

// DES round function (Feistel)
feistel :: proc(right: u32, subkey: u64) -> u32 {
	// Expand right from 32 to 48 bits
	expanded := permute_block(u64(right), expansion_function[:])

	// XOR with subkey
	temp := expanded ~ subkey

	// S-box substitution (48 bits -> 32 bits)
	output: u32 = 0

	for i in 0 ..< 8 {
		// Extract 6 bits for this S-box (from left to right)
		shift := 42 - (i * 6)
		six_bits := u8((temp >> uint(shift)) & 0x3F)

		// Row = bits 0 and 5, Column = bits 1-4
		row := ((six_bits >> 4) & 0x02) | (six_bits & 0x01)
		col := (six_bits >> 1) & 0x0F

		// Lookup in S-box
		s_output := s_boxes[i][row][col]

		// Place in output (4 bits at a time, from left to right)
		output |= u32(s_output) << uint(28 - (i * 4))
	}

	// Apply permutation
	result := permute_block(u64(output), permutation_function[:])
	return u32(result)
}

// DES encryption/decryption of single block
des_crypt :: proc(input: []u8, output: []u8, subkeys: ^[16]u64) {
	// Convert input to u64 (big-endian)
	block: u64 = 0
	for i in 0 ..< 8 {
		block = (block << 8) | u64(input[i])
	}

	// Initial permutation
	block = permute_block(block, initial_permutation[:])

	// Split into left and right
	left := u32(block >> 32)
	right := u32(block & 0xFFFFFFFF)

	// 16 rounds
	for round in 0 ..< 16 {
		new_right := left ~ feistel(right, subkeys[round])
		left = right
		right = new_right
	}

	// Combine (note: left and right are swapped after 16 rounds)
	preoutput := (u64(right) << 32) | u64(left)

	// Final permutation
	result := permute_block(preoutput, final_permutation[:])

	// Convert back to bytes (big-endian)
	for i := 7; i >= 0; i -= 1 {
		output[7 - i] = u8((result >> uint(i * 8)) & 0xFF)
	}
}

// CBC mode encryption
des_cbc_encrypt :: proc(plaintext: []u8, ciphertext: []u8, key: []u8, iv: []u8) {
	subkeys: [16]u64
	des_key_setup(key, &subkeys, .Encrypt)

	prev_block: [DES_BLOCK_SIZE]u8
	copy(prev_block[:], iv)

	num_blocks := len(plaintext) / DES_BLOCK_SIZE

	for block_idx in 0 ..< num_blocks {
		input_offset := block_idx * DES_BLOCK_SIZE
		output_offset := block_idx * DES_BLOCK_SIZE

		// XOR with previous ciphertext block (or IV)
		xored: [DES_BLOCK_SIZE]u8
		for i in 0 ..< DES_BLOCK_SIZE {
			xored[i] = plaintext[input_offset + i] ~ prev_block[i]
		}

		// Encrypt
		des_crypt(xored[:], ciphertext[output_offset:], &subkeys)

		// Save ciphertext for next round
		copy(prev_block[:], ciphertext[output_offset:output_offset + DES_BLOCK_SIZE])
	}
}

// CBC mode decryption
des_cbc_decrypt :: proc(ciphertext: []u8, plaintext: []u8, key: []u8, iv: []u8) {
	subkeys: [16]u64
	des_key_setup(key, &subkeys, .Decrypt)

	prev_block: [DES_BLOCK_SIZE]u8
	copy(prev_block[:], iv)

	num_blocks := len(ciphertext) / DES_BLOCK_SIZE

	for block_idx in 0 ..< num_blocks {
		input_offset := block_idx * DES_BLOCK_SIZE
		output_offset := block_idx * DES_BLOCK_SIZE

		// Save current ciphertext block before decryption
		current_block: [DES_BLOCK_SIZE]u8
		copy(current_block[:], ciphertext[input_offset:input_offset + DES_BLOCK_SIZE])

		// Decrypt
		temp: [DES_BLOCK_SIZE]u8
		des_crypt(ciphertext[input_offset:], temp[:], &subkeys)

		// XOR with previous ciphertext block (or IV)
		for i in 0 ..< DES_BLOCK_SIZE {
			plaintext[output_offset + i] = temp[i] ~ prev_block[i]
		}

		// Update previous block
		copy(prev_block[:], current_block[:])
	}
}

// PKCS7 padding
pkcs7_pad :: proc(data: []u8, block_size: int, allocator := context.allocator) -> []u8 {
	padding_len := block_size - (len(data) % block_size)
	if padding_len == 0 {
		padding_len = block_size
	}

	padded := make([]u8, len(data) + padding_len, allocator)
	copy(padded, data)

	for i in len(data) ..< len(padded) {
		padded[i] = u8(padding_len)
	}

	return padded
}

// PKCS7 unpadding
pkcs7_unpad :: proc(data: []u8) -> ([]u8, bool) {
	if len(data) == 0 {
		return nil, false
	}

	padding_len := int(data[len(data) - 1])

	if padding_len == 0 || padding_len > len(data) {
		return nil, false
	}

	for i in len(data) - padding_len ..< len(data) {
		if data[i] != u8(padding_len) {
			return nil, false
		}
	}

	return data[:len(data) - padding_len], true
}

