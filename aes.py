# REFERENCING: AES Standard, Block Breakers (https://davidwong.fr/blockbreakers/aes.html)

from lookups_constants import (
    sbox,
    inv_sbox,
    rcon,
    multiply_by_2,
    multiply_by_3,
    multiply_by_9,
    multiply_by_11,
    multiply_by_13,
    multiply_by_14,
)

# ==============================================================================
#                            KEY EXPANSION
# ==============================================================================

#  AES-128 => we need 11 keys


# "Word" as in 4 bytes
def RotWord(word):
    return word[1:] + [word[0]]


def SubWord(word):
    return [sbox[x] for x in word]


def Rcon(x):
    return [rcon[x], 0x00, 0x00, 0x00]


# Assuming key as a 2d array for ease of implementation
def KeyExpansion(key):
    expanded_keys = [key]

    for round in range(10):
        prev_round_key = expanded_keys[-1]
        curr_round_key = []

        # Extract last column
        last_col = [prev_round_key[row][-1] for row in range(4)]

        # Perform transformations
        rotated = RotWord(last_col)
        substituted = SubWord(rotated)
        rcon_col = Rcon(round + 1)  # Rcon index should start from 1

        # Compute first column of new round key
        first_col = [
            substituted[j] ^ prev_round_key[j][0] ^ rcon_col[j] for j in range(4)
        ]
        curr_round_key.append(first_col)

        # Compute remaining columns
        for col in range(1, 4):
            new_col = [
                curr_round_key[col - 1][j] ^ prev_round_key[j][col] for j in range(4)
            ]
            curr_round_key.append(new_col)

        # Transpose to maintain column-major order
        curr_round_key = [
            [curr_round_key[col][row] for col in range(4)] for row in range(4)
        ]
        expanded_keys.append(curr_round_key)

    return expanded_keys


# ==============================================================================
#                            AES ENCRYPTION FUNCTIONS
# ==============================================================================


def SubBytes(state):
    return [[sbox[elem] for elem in row] for row in state]


def ShiftRows(state):
    # Row 1: No shift
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]

    return state


def MixColumns(state):
    # Column i : state[0][i], state[1][i], state[2][i], state[3][i]
    for i in range(4):
        a0, a1, a2, a3 = state[0][i], state[1][i], state[2][i], state[3][i]

        state[0][i] = multiply_by_2[a0] ^ multiply_by_3[a1] ^ a2 ^ a3
        state[1][i] = multiply_by_2[a1] ^ multiply_by_3[a2] ^ a3 ^ a0
        state[2][i] = multiply_by_2[a2] ^ multiply_by_3[a3] ^ a0 ^ a1
        state[3][i] = multiply_by_2[a3] ^ multiply_by_3[a0] ^ a1 ^ a2

    return state


def AddRoundKey(state, round_key):
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[i][j]
    return state


def encrypt(state, round_keys):
    # pre-whitening ie., xor-ing state with first round key
    state = AddRoundKey(state, round_keys[0])
    print(f"Pre-whitening: {matrix_to_hex_string(state)}")
    # n - 1 rounds
    for i in range(1, 10):
        print(f"Round {i} start: {matrix_to_hex_string(state)}")
        state = SubBytes(state)
        print(f"SubBytes: {matrix_to_hex_string(state)}")

        state = ShiftRows(state)
        print(f"ShiftRows: {matrix_to_hex_string(state)}")

        state = MixColumns(state)
        print(f"MixColumns: {matrix_to_hex_string(state)}")

        state = AddRoundKey(state, round_keys[i])
        print()

    # last round with absence of MixColumns
    print(f"Last Round start: {matrix_to_hex_string(state)}")
    state = SubBytes(state)
    print(f"SubBytes: {matrix_to_hex_string(state)}")

    state = ShiftRows(state)
    print(f"ShiftRows: {matrix_to_hex_string(state)}")
    state = AddRoundKey(state, round_keys[10])
    print()

    return state


# ==============================================================================
#                            AES DECRYPTION FUNCTIONS
# ==============================================================================


def InvShiftRows(state):
    # Row 1: No shift
    state[1] = state[1][3:] + state[1][:3]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][1:] + state[3][:1]

    return state


def InvSubBytes(state):
    return [[inv_sbox[elem] for elem in row] for row in state]


def InvMixColumns(state):
    # Column i : state[0][i], state[1][i], state[2][i], state[3][i]
    for i in range(4):
        a0, a1, a2, a3 = state[0][i], state[1][i], state[2][i], state[3][i]

        state[0][i] = (
            multiply_by_14[a0]
            ^ multiply_by_11[a1]
            ^ multiply_by_13[a2]
            ^ multiply_by_9[a3]
        )
        state[1][i] = (
            multiply_by_14[a1]
            ^ multiply_by_11[a2]
            ^ multiply_by_13[a3]
            ^ multiply_by_9[a0]
        )
        state[2][i] = (
            multiply_by_14[a2]
            ^ multiply_by_11[a3]
            ^ multiply_by_13[a0]
            ^ multiply_by_9[a1]
        )
        state[3][i] = (
            multiply_by_14[a3]
            ^ multiply_by_11[a0]
            ^ multiply_by_13[a1]
            ^ multiply_by_9[a2]
        )

    return state


def decrypt(state, round_keys):
    # inverse of pre-whitening ie., xor-ing state with last round key
    state = AddRoundKey(state, round_keys[10])
    print(f"Inverse Pre-whitening: {matrix_to_hex_string(state)}")
    # n - 1 rounds
    for i in range(9, 0, -1):
        print(f"Inverse Round {i} start: {matrix_to_hex_string(state)}")

        state = InvShiftRows(state)
        print(f"InvShiftRows: {matrix_to_hex_string(state)}")

        state = InvSubBytes(state)
        print(f"InvSubBytes: {matrix_to_hex_string(state)}")

        state = AddRoundKey(state, round_keys[i])
        print(f"AddRoundKey: {matrix_to_hex_string(state)}")

        state = InvMixColumns(state)

        print()

    # last round with absence of MixColumns
    print(f"Last Round start: {matrix_to_hex_string(state)}")

    state = InvShiftRows(state)
    print(f"InvShiftRows: {matrix_to_hex_string(state)}")

    state = InvSubBytes(state)
    print(f"InvSubBytes: {matrix_to_hex_string(state)}")

    state = AddRoundKey(state, round_keys[0])

    print()

    return state


# ==============================================================================
#                           HELPER FUNCTIONS
# ==============================================================================


def hex_string_to_matrix(hex_string):
    """Converts a 32-character hex string into a 4x4 column-major order matrix."""
    bytes_list = [int(hex_string[i : i + 2], 16) for i in range(0, len(hex_string), 2)]
    return [bytes_list[i::4] for i in range(4)]  # Convert to 4x4 matrix


def matrix_to_hex_string(matrix):
    """Converts a 4x4 matrix back to a hex string."""
    flat_list = [
        matrix[row][col] for col in range(4) for row in range(4)
    ]  # Column-major order
    return "".join(f"{byte:02x}" for byte in flat_list)


# ==============================================================================
#                                   MAIN
# ==============================================================================


if __name__ == "__main__":
    # Example key as a hex string (Taken from example vector in Appendix C of AES Standard)
    hex_key = "000102030405060708090a0b0c0d0e0f"
    # hex_key = "d6aa74fdd2af72fadaa678f1d6ab76fe"
    print(f"Initial Key: {hex_key}")

    key_matrix = hex_string_to_matrix(hex_key)

    # Generate round keys
    round_keys = KeyExpansion(key_matrix)
    # Print the round keys in hex format
    print("Expanded Round Keys:")
    for i, round_key in enumerate(round_keys):
        print(f"Round {i}: {matrix_to_hex_string(round_key)}")

    # Example plaintext as hex string (Taken from example vector in Appendix C of AES Standard)
    hex_plain_text = "00112233445566778899aabbccddeeff"
    start_state = hex_string_to_matrix(hex_plain_text)
    print("Plaintext Start State:")
    for row in start_state:
        print([hex(x)[2:].zfill(2) for x in row])  # Print matrix in hex format

    print()

    encrypted = encrypt(start_state, round_keys)
    print(f"Encryption Result: {matrix_to_hex_string(encrypted)}")

    print()

    decrypted = decrypt(encrypted, round_keys)
    print(f"Decryption Result: {matrix_to_hex_string(decrypted)}")
