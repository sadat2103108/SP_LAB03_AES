def bytes_to_matrix(data):

    if len(data) != 16:
        raise ValueError("AES block must contain exactly 16 bytes")

    return [[data[row + 4 * col] for col in range(4)] for row in range(4)]


def matrix_to_bytes(state):

    return bytes(state[row][col] for col in range(4) for row in range(4))



SBOX = [
    0x63,
    0x7C,
    0x77,
    0x7B,
    0xF2,
    0x6B,
    0x6F,
    0xC5,
    0x30,
    0x01,
    0x67,
    0x2B,
    0xFE,
    0xD7,
    0xAB,
    0x76,
    0xCA,
    0x82,
    0xC9,
    0x7D,
    0xFA,
    0x59,
    0x47,
    0xF0,
    0xAD,
    0xD4,
    0xA2,
    0xAF,
    0x9C,
    0xA4,
    0x72,
    0xC0,
    0xB7,
    0xFD,
    0x93,
    0x26,
    0x36,
    0x3F,
    0xF7,
    0xCC,
    0x34,
    0xA5,
    0xE5,
    0xF1,
    0x71,
    0xD8,
    0x31,
    0x15,
    0x04,
    0xC7,
    0x23,
    0xC3,
    0x18,
    0x96,
    0x05,
    0x9A,
    0x07,
    0x12,
    0x80,
    0xE2,
    0xEB,
    0x27,
    0xB2,
    0x75,
    0x09,
    0x83,
    0x2C,
    0x1A,
    0x1B,
    0x6E,
    0x5A,
    0xA0,
    0x52,
    0x3B,
    0xD6,
    0xB3,
    0x29,
    0xE3,
    0x2F,
    0x84,
    0x53,
    0xD1,
    0x00,
    0xED,
    0x20,
    0xFC,
    0xB1,
    0x5B,
    0x6A,
    0xCB,
    0xBE,
    0x39,
    0x4A,
    0x4C,
    0x58,
    0xCF,
    0xD0,
    0xEF,
    0xAA,
    0xFB,
    0x43,
    0x4D,
    0x33,
    0x85,
    0x45,
    0xF9,
    0x02,
    0x7F,
    0x50,
    0x3C,
    0x9F,
    0xA8,
    0x51,
    0xA3,
    0x40,
    0x8F,
    0x92,
    0x9D,
    0x38,
    0xF5,
    0xBC,
    0xB6,
    0xDA,
    0x21,
    0x10,
    0xFF,
    0xF3,
    0xD2,
    0xCD,
    0x0C,
    0x13,
    0xEC,
    0x5F,
    0x97,
    0x44,
    0x17,
    0xC4,
    0xA7,
    0x7E,
    0x3D,
    0x64,
    0x5D,
    0x19,
    0x73,
    0x60,
    0x81,
    0x4F,
    0xDC,
    0x22,
    0x2A,
    0x90,
    0x88,
    0x46,
    0xEE,
    0xB8,
    0x14,
    0xDE,
    0x5E,
    0x0B,
    0xDB,
    0xE0,
    0x32,
    0x3A,
    0x0A,
    0x49,
    0x06,
    0x24,
    0x5C,
    0xC2,
    0xD3,
    0xAC,
    0x62,
    0x91,
    0x95,
    0xE4,
    0x79,
    0xE7,
    0xC8,
    0x37,
    0x6D,
    0x8D,
    0xD5,
    0x4E,
    0xA9,
    0x6C,
    0x56,
    0xF4,
    0xEA,
    0x65,
    0x7A,
    0xAE,
    0x08,
    0xBA,
    0x78,
    0x25,
    0x2E,
    0x1C,
    0xA6,
    0xB4,
    0xC6,
    0xE8,
    0xDD,
    0x74,
    0x1F,
    0x4B,
    0xBD,
    0x8B,
    0x8A,
    0x70,
    0x3E,
    0xB5,
    0x66,
    0x48,
    0x03,
    0xF6,
    0x0E,
    0x61,
    0x35,
    0x57,
    0xB9,
    0x86,
    0xC1,
    0x1D,
    0x9E,
    0xE1,
    0xF8,
    0x98,
    0x11,
    0x69,
    0xD9,
    0x8E,
    0x94,
    0x9B,
    0x1E,
    0x87,
    0xE9,
    0xCE,
    0x55,
    0x28,
    0xDF,
    0x8C,
    0xA1,
    0x89,
    0x0D,
    0xBF,
    0xE6,
    0x42,
    0x68,
    0x41,
    0x99,
    0x2D,
    0x0F,
    0xB0,
    0x54,
    0xBB,
    0x16,
]



INV_SBOX = [0] * 256

for i, value in enumerate(SBOX):
    INV_SBOX[value] = i


def inv_sub_bytes(state):

    for row in range(4):
        for col in range(4):
            state[row][col] = INV_SBOX[state[row][col]]

    return state


def inv_shift_rows(state):

    for row in range(4):
        state[row] = state[row][-row:] + state[row][:-row] if row != 0 else state[row]

    return state


def add_round_key(state, round_key):

    for row in range(4):
        for col in range(4):
            state[row][col] ^= round_key[row][col]

    return state


def gf_multiply(a, b):

    result = 0

    for _ in range(8):

        if b & 1:
            result ^= a

        high_bit = a & 0x80

        a = (a << 1) & 0xFF

        if high_bit:
            a ^= 0x1B

        b >>= 1

    return result


def inv_mix_columns(state):

    for col in range(4):

        a0 = state[0][col]
        a1 = state[1][col]
        a2 = state[2][col]
        a3 = state[3][col]

        state[0][col] = (
            gf_multiply(a0, 0x0E)
            ^ gf_multiply(a1, 0x0B)
            ^ gf_multiply(a2, 0x0D)
            ^ gf_multiply(a3, 0x09)
        )

        state[1][col] = (
            gf_multiply(a0, 0x09)
            ^ gf_multiply(a1, 0x0E)
            ^ gf_multiply(a2, 0x0B)
            ^ gf_multiply(a3, 0x0D)
        )

        state[2][col] = (
            gf_multiply(a0, 0x0D)
            ^ gf_multiply(a1, 0x09)
            ^ gf_multiply(a2, 0x0E)
            ^ gf_multiply(a3, 0x0B)
        )

        state[3][col] = (
            gf_multiply(a0, 0x0B)
            ^ gf_multiply(a1, 0x0D)
            ^ gf_multiply(a2, 0x09)
            ^ gf_multiply(a3, 0x0E)
        )

    return state


RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def rot_word(word):
    

    return word[1:] + word[:1]


def sub_word(word):
    
    return [SBOX[b] for b in word]


def key_expansion(key):
  

    if len(key) != 16:
        raise ValueError("AES-128 key must contain exactly 16 bytes")

    words = [list(key[i : i + 4]) for i in range(0, 16, 4)]

    
    for i in range(4, 44):

        temp = words[i - 1].copy()

        if i % 4 == 0:

            temp = rot_word(temp)
            temp = sub_word(temp)

            rcon_value = RCON[i // 4]

            temp[0] ^= rcon_value

        new_word = [words[i - 4][j] ^ temp[j] for j in range(4)]

        words.append(new_word)

    round_keys = []

    for round_number in range(11):

        round_key_bytes = []

        for word in words[round_number * 4 : round_number * 4 + 4]:
            round_key_bytes.extend(word)

        round_keys.append(bytes_to_matrix(round_key_bytes))

    return round_keys


def aes128_decrypt(ciphertext, key):

    if len(ciphertext) != 16:
        raise ValueError("Ciphertext must contain exactly 16 bytes")

    if len(key) != 16:
        raise ValueError("Key must contain exactly 16 bytes")

    
    round_keys = key_expansion(key)


    state = bytes_to_matrix(ciphertext)

    add_round_key(state, round_keys[10])

    for round_number in range(9, 0, -1):

        inv_shift_rows(state)

        inv_sub_bytes(state)

        add_round_key(state, round_keys[round_number])

        inv_mix_columns(state)

    
    inv_shift_rows(state)

    inv_sub_bytes(state)

    add_round_key(state, round_keys[0])

    
    plaintext = matrix_to_bytes(state)

    return plaintext


if __name__ == "__main__":


    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

    ciphertext = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")

    expected_plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")

    plaintext = aes128_decrypt(ciphertext, key)


    print("Secret Key       :", key.hex())
    print("Ciphertext       :", ciphertext.hex())
    print("Decrypted Text   :", plaintext.hex())
    print("Expected Text    :", expected_plaintext.hex())


    if plaintext == expected_plaintext:

        print("RESULT: AES-128 DECRYPTION SUCCESSFUL!")

    else:

        print("RESULT: DECRYPTION FAILED!")