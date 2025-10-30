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
            0x5, 0x9, 0x0, 0x7
            ]

    def __init__(self, master_key: int, num_rounds: int, verbose=False):
        self.master_key = master_key
        self.verbose = verbose
        self.round_keys = None
        self.num_rounds = num_rounds

    def encrypt_round(self, state: int, round_index: int, final_round=False):
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
                f"  after initial AddRoundKey: {state:016b}, rk={self.round_keys[0]:016b}")

        for r in range(self.num_rounds):
            final = r == self.num_rounds - 1
            if self.verbose:
                print(f"Round {r+1}/{self.num_rounds}")
            state = self.encrypt_round(state, r, final)

        return state

    def decrypt(self):
        pass

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

    def mix_columns(self, state: int) -> int:
        """
        Mixes the columns of a 2x2 nibble matrix using XOR.

        Args:
            state (int): 16-bit integer
        Returns:
            int: new 16-bit state after mixing columns
        Example:
            state = 0x1234 (matrix: [[1, 2], [3, 4]])
            c0 = 1 ^ 3 = 2
            c1 = 2 ^ 4 = 6
            c2 = 3 ^ 1 = 2
            c3 = 4 ^ 2 = 6
            returns: 0x2626
        """
        s0 = (state >> 12) & 0xF
        s1 = (state >> 8) & 0xF
        s2 = (state >> 4) & 0xF
        s3 = state & 0xF

        c0 = s0 ^ s2
        c1 = s1 ^ s3
        c2 = s2 ^ s0
        c3 = s3 ^ s1

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


if __name__ == "__main__":
    MASTER_KEY = 0b1010010110100101
    PLAINTEXT = 0b1100101011010001
    NUM_ROUNDS = 3

    aes = BabyAES(master_key=MASTER_KEY, num_rounds=NUM_ROUNDS, verbose=True)

    print("====ENCRYPT====")
    ciphertext = aes.encrypt(PLAINTEXT)

    print("\nRESULTS")
    print(f" Plaintext: {PLAINTEXT:016b}")
    print(f" Ciphertext: {ciphertext:016b}")
