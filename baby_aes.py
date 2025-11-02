"""
Implementation of BabyAES
"""


class BabyAES:
    """
    A reduced AES variant operating on a 16-bit data block with a 2x2 state matrix. 
    The implementation allows adjusting the number of rounds for analysis.
    """

    SBOX = [0xE, 0x4, 0xD, 0x1,
            0x2, 0xF, 0xB, 0x8,
            0x3, 0xA, 0x6, 0xC,
            0x5, 0x9, 0x0, 0x7]
    INV_SBOX = [0xE, 0x3, 0x4, 0x8,
                0x1, 0xC, 0xA, 0xF,
                0x7, 0xD, 0x9, 0x6,
                0xB, 0x2, 0x0, 0x5]

    def __init__(self, master_key: int, num_rounds: int, verbose=False):
        self.master_key = master_key
        self.verbose = verbose
        self.round_keys = None
        self.num_rounds = num_rounds

    def encrypt_round(self, state: int, round_index: int, final_round=False) -> int:
        """
        Performs one round of BabyAES encryption: 
        SubBytes, ShiftRows, MixColumns (skipped in the final round) and AddRoundKey.

        Args:
            state (int): 16-bit current state
            round_index (int): round key index
            final_round (bool): skip MixColumns if True
        Returns:
            int: new 16-bit state
        """
        if self.verbose:
            print(f"    start round state: {state:016b}")
        state = self.sub_bytes(state)
        if self.verbose:
            print(f"    after SubBytes: {state:016b}")
        state = self.shift_rows(state)
        if self.verbose:
            print(f"    after ShiftRows: {state:016b}")
        if not final_round:
            state = self.mix_columns(state)
            if self.verbose:
                print(f"    after MixColumns: {state:016b}")
        state = self.add_round_key(state, round_index)
        if self.verbose:
            print(
                f"    after AddRoundKey: {state:016b}, rk={self.round_keys[round_index]:016b}")

        return state

    def encrypt(self, pt: int) -> int:
        """
        Encrypts a 16-bit plaintext using BabyAES.

        Args:
            pt (int): 16-bit plaintext to encrypt
        Returns:
            int: 16-bit ciphertext
        """
        self.round_keys = self.key_expansion()
        state = pt & 0xFFFF

        if self.verbose:
            print(f"PT: {state:016b} KEY: {self.master_key:016b}")

        state = self.add_round_key(state, 0)

        if self.verbose:
            print(
                f"  after AddRoundKey (round key 0): {state:016b}, rk={self.round_keys[0]:016b}")

        for r in range(self.num_rounds):
            final = r == self.num_rounds - 1
            if self.verbose:
                print(f"Round {r+1}/{self.num_rounds}")
            state = self.encrypt_round(state, r, final)

        return state

    def decrypt_round(self, state: int, round_index: int, final_round=False) -> int:
        """
        Performs one round of BabyAES decryption:
        AddRoundKey, MixColumns (if not final), InvShiftRows, InvSubBytes.
        """
        if self.verbose:
            print(f"    start round state: {state:016b}")
        state = self.add_round_key(state, round_index)
        if self.verbose:
            print(
                f"    after AddRoundKey: {state:016b}, rk={self.round_keys[round_index]:016b}")
        if not final_round:
            state = self.mix_columns(state)
            if self.verbose:
                print(f"    after MixColumns: {state:016b}")
        state = self.inv_shift_rows(state)
        if self.verbose:
            print(f"    after InvShiftRows: {state:016b}")
        state = self.inv_sub_bytes(state)
        if self.verbose:
            print(f"    after InvSubBytes: {state:016b}")

        return state

    def decrypt(self, ct: int) -> int:
        """
        Decrypts a 16-bit ciphertext using BabyAES.
        """
        self.round_keys = self.key_expansion()
        state = ct & 0xFFFF

        if self.verbose:
            print(f"CT: {state:016b} KEY: {self.master_key:016b}")

        for r in range(self.num_rounds-1, -1, -1):
            final = r == self.num_rounds - 1
            if self.verbose:
                print(f"Round {r+1}/{self.num_rounds}")
            state = self.decrypt_round(state, r, final)

        state = self.add_round_key(state, 0)

        if self.verbose:
            print(
                f"  after AddRoundKey (round key 0): {state:016b}, rk={self.round_keys[0]:016b}")

        return state

    def key_expansion(self) -> list[int]:
        """
        Expands the master key into round keys for BabyAES.

        Each round key is derived by rotating the master key left by 4*i bits for round i,
        then masking the result to 16 bits. The first round key is simply the master key itself.

        Returns:
            list[int]: list of 16-bit round keys
        Example:
            self.master_key = 0x1234
            self.num_rounds = 3
            round_keys: [0x1234, 0x2341, 0x3412, 0x4123]
        """
        round_keys = [self.master_key]
        for i in range(1, self.num_rounds + 1):
            rotated = ((self.master_key << (4 * i)) &
                       0xFFFF) | ((self.master_key) >> (16 - 4 * i))
            round_keys.append(rotated)
        return round_keys

    def sub_bytes(self, state: int) -> int:
        """
        Substitutes each 4-bit nibble in a 16-bit state using SBOX.

        Args:
            state (int): 16-bit integer
        Returns:
            int: new 16-bit state after substituting each nibble
        Example:
            state = 0x3210 (bits: 0011 0010 0001 0000)
            SBOX = [0xE, 0x4, 0xD, 0x1, ...]
            nibble 1 (0x3) -> SBOX[3] = 1
            nibble 2 (0x2) -> SBOX[2] = D
            nibble 3 (0x1) -> SBOX[1] = 4
            nibble 4 (0x0) -> SBOX[0] = E
            returns: 0x1D4E (0001 1101 0100 1110)
        """
        s0 = self.SBOX[(state >> 12) & 0xF]
        s1 = self.SBOX[(state >> 8) & 0xF]
        s2 = self.SBOX[(state >> 4) & 0xF]
        s3 = self.SBOX[state & 0xF]
        return (s0 << 12) | (s1 << 8) | (s2 << 4) | s3

    def shift_rows(self, state: int) -> int:
        """
        Shifts the rows of a 2x2 nibble matrix.

        Args:
            state (int): 16-bit integer
        Returns:
            int: new 16-bit state after shifting rows
        Example:
            state = 0x1234 (matrix: [[1, 2], [3, 4]])
            first row unchanged: [1, 2]
            second row rotated left by 1 nibble: [4, 3]
            returns: 0x1243
        """
        s0 = (state >> 12) & 0xF
        s1 = (state >> 8) & 0xF
        s2 = (state >> 4) & 0xF
        s3 = state & 0xF

        return (s0 << 12) | (s1 << 8) | (s3 << 4) | s2

    def gf_mul(self, a: int, b: int) -> int:
        """
        Galois field multiplication of a and b in GF(2^4) using irreducible polynomial: 
        x^4 + x + 1 (0b10011).

        Args:
            a (int): first 4-bit operand
            b (int): second 4-bit operand
        Returns:
            int: product of a and b reduced to 4 bits
        Example:
            gf_mult(0x3, 0x7) -> 0x9
        """
        product = 0

        for _ in range(4):
            if b & 1:
                product ^= a
            a = ((a << 1) ^ 0b10011) if a & 0b1000 else (a << 1)
            b >>= 1

        return product & 0xF

    def mix_columns(self, state: int) -> int:
        """
        Mixes the columns of a 2x2 nibble matrix using Galois Field GF(2^4) arithmetic.

        Each column [s0, s2] and [s1, s2] is multiplied by the constant matrix:
            [2 3]
            [3 2]

        Args:
            state (int): 16-bit integer
        Returns:
            int: new 16-bit state after mixing columns
        Example:
            state = 0x1234 (matrix: [[1, 2], [3, 4]])
            Column 1: c0 = 7, c2 = 5
            Column 2: c1 = 8, c3 = 14
            returns: 0x785E
        """
        s0 = (state >> 12) & 0xF
        s1 = (state >> 8) & 0xF
        s2 = (state >> 4) & 0xF
        s3 = state & 0xF

        c0 = self.gf_mul(2, s0) ^ self.gf_mul(3, s2)
        c1 = self.gf_mul(2, s1) ^ self.gf_mul(3, s3)
        c2 = self.gf_mul(3, s0) ^ self.gf_mul(2, s2)
        c3 = self.gf_mul(3, s1) ^ self.gf_mul(2, s3)

        return (c0 << 12) | (c1 << 8) | (c2 << 4) | c3

    def add_round_key(self, state: int, round_index: int) -> int:
        """
        The 16-bit round key is XORed with the 16-bit state.

        Args:
            state (int): 16-bit integer
            round_index (int): index of the round key to use
        Returns:
            int: New 16-bit state after XOR with the round key.
        """
        round_key = self.round_keys[round_index]
        return state ^ round_key

    def inv_sub_bytes(self, state: int) -> int:
        """
        Inverse of SybBytes: substitutes nibbles using INV_SBOX.
        """
        s0 = self.INV_SBOX[(state >> 12) & 0xF]
        s1 = self.INV_SBOX[(state >> 8) & 0xF]
        s2 = self.INV_SBOX[(state >> 4) & 0xF]
        s3 = self.INV_SBOX[state & 0xF]

        return (s0 << 12) | (s1 << 8) | (s2 << 4) | s3

    def inv_shift_rows(self, state: int) -> int:
        """
        Inverse of ShiftRows: rotates second row back to original position.
        """
        s0 = (state >> 12) & 0xF
        s1 = (state >> 8) & 0xF
        s2 = (state >> 4) & 0xF
        s3 = state & 0xF

        return (s0 << 12) | (s1 << 8) | (s3 << 4) | s2


if __name__ == "__main__":
    MASTER_KEY = 0b1010010110100101
    PLAINTEXT = 0b0001101110111101
    NUM_ROUNDS = 3

    aes = BabyAES(master_key=MASTER_KEY, num_rounds=NUM_ROUNDS, verbose=True)

    print("====ENCRYPT====")
    ciphertext = aes.encrypt(PLAINTEXT)

    print("\nRESULTS")
    print(f" Plaintext:  {PLAINTEXT:016b} (0x{PLAINTEXT:04X})")
    print(f" Ciphertext: {ciphertext:016b} (0x{ciphertext:04X})")

    print("\n\n===DECRYPT===")
    decrypted = aes.decrypt(ciphertext)
    print("\nRESULTS")
    print(f" Decrypted:  {decrypted:016b} (0x{decrypted:04X})")
