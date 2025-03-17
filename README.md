# Python AES-128: A Simple Implementation

Assignment work done for the **CS1702** (Network Security) course of our 6th Semester.

## Table of Contents

- [Python AES-128: A Simple Implementation](#python-aes-128-a-simple-implementation)
  - [Table of Contents](#table-of-contents)
  - [Aim](#aim)
  - [Implementation](#implementation)
    - [Key Components](#key-components)
    - [Encryption Process](#encryption-process)
    - [Decryption Process](#decryption-process)
    - [Helper Functions](#helper-functions)
  - [Results](#results)
  - [References](#references)

## Aim

The primary goal of the assignment was to implement the Advanced Encryption Standard (AES-128) in Python to understand its core principles and functionality. AES is a widely used symmetric encryption algorithm, known for its speed and security, making it a standard choice for data encryption in various applications. By implementing AES-128, we gain a deeper insight into how block ciphers work.

## Implementation

This implementation of AES-128 follows the standard as defined by NIST (National Institute of Standards and Technology). The code is structured to clearly demonstrate each step of the encryption and decryption process.

### Key Components

1. **Key Expansion:** Generates 11 round keys (10 rounds + initial round) from the original 128-bit key.
   - `RotWord()`: Performs a cyclic permutation on a 4-byte word.
   - `SubWord()`: Substitutes each byte in a word using the AES S-box.
   - `Rcon()`: Applies the round constant to assist in key expansion.

2. **Lookup Tables:** For ease of implementation, and to optimize computations, the implementation uses pre-computed lookup tables for:
   - S-box and inverse S-box for SubBytes transformation
   - Multiplication tables for MixColumns operation (multiply by 2, 3, 9, 11, 13, 14 within the Galois Field 2⁸ (GF(2⁸)))
   - Round constants (Rcon) for key expansion

### Encryption Process

The encryption process follows these steps:

1. **Pre-whitening:** XORs the initial state with the first round key.
2. **Main Rounds (1-9):** Each round consists of four transformations:
   - `SubBytes()`: Substitutes each byte using the S-box.
   - `ShiftRows()`: Cyclically shifts the rows of the state.
   - `MixColumns()`: Mixes data within each column using a linear transformation.
   - `AddRoundKey()`: XORs the state with the round key.

3. **Final Round (10)**: Identical to the main rounds but without the MixColumns step.

### Decryption Process

The decryption process mirrors the encryption process in reverse:

1. **Initial AddRoundKey:** XORs the state with the last round key.
2. **Main Rounds (9-1):** Each round consists of:
   - `InvShiftRows()`: Inverse of ShiftRows.
   - `InvSubBytes()`: Inverse of SubBytes using the inverse S-box.
   - `AddRoundKey()`: XORs the state with the round key.
   - `InvMixColumns()`: Inverse of MixColumns.

3. **Final Round:** Includes InvShiftRows, InvSubBytes, and AddRoundKey with the initial key.

### Helper Functions

- `hex_string_to_matrix()`: Converts a 32-character hex string into a 4x4 matrix in column-major order.
- `matrix_to_hex_string()`: Converts a 4x4 matrix back to a hex string.
- Debug printing functions to visualize the state after each transformation.

## Results

The implementation successfully encrypts and decrypts data using AES-128. The code includes test vectors from Appendix C of the AES Standard to verify correctness. The implementation demonstrates the full AES process, including key expansion, encryption, and decryption, with detailed logging of state transformations at each step.

## References

- David Wong's **Block Breakers** - <https://davidwong.fr/blockbreakers/aes.html>
- The official AES Standard - <http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf>
- boppreh's AES Implementation in Python - <https://github.com/boppreh/aes>
