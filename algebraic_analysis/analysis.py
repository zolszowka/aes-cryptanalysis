import sys
import os
import time

script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(script_dir)
sys.path.append(parent_dir)

OUTPUT_DIR = os.path.join(script_dir, "algebraic_results")

if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

try:
    from baby_aes import BabyAES
    REAL_SBOX = BabyAES.SBOX
    print(f"Loaded BabyAES module")
except ImportError:
    print("[ERROR]")
    sys.exit(1)

class SymbolicBit:

    def __init__(self, terms=None):
        self.terms = terms if terms is not None else set()

    @staticmethod
    def var(name):
        return SymbolicBit({frozenset([name])})

    @staticmethod
    def const(val):
        return SymbolicBit({frozenset(["1"])}) if val == 1 else SymbolicBit()

    def __add__(self, other):
        return SymbolicBit(self.terms ^ other.terms)

    def __mul__(self, other):
        new_terms = set()
        for t1 in self.terms:
            for t2 in other.terms:
                if "1" in t1: new_term = t2
                elif "1" in t2: new_term = t1
                else: new_term = t1 | t2
                
                if new_term in new_terms: new_terms.remove(new_term)
                else: new_terms.add(new_term)
        return SymbolicBit(new_terms)

    def to_full_string(self):
        if not self.terms: return "0"
        res = []
        sorted_terms = sorted(list(self.terms), key=lambda x: (len(x), sorted(list(x))))
        
        for term in sorted_terms:
            if "1" in term and len(term) == 1:
                res.append("1")
            else:
                vars_sorted = sorted([v for v in term if v != "1"])
                res.append("".join(vars_sorted))
        return " + ".join(res)

def get_anf_coeffs(sbox):
    eqs = []
    for bit in range(4):
        truth_table = [(sbox[i] >> bit) & 1 for i in range(16)]
        coeffs = list(truth_table)
        for i in range(4):
            for j in range(16):
                if (j & (1 << i)): coeffs[j] ^= coeffs[j ^ (1 << i)]
        eqs.append(coeffs)
    return eqs

def sbox_symbolic(nibble, anf_coeffs):
    b3, b2, b1, b0 = nibble
    outputs = []
    for bit_idx in range(4):
        coeffs = anf_coeffs[bit_idx]
        y = SymbolicBit()
        for i in range(16):
            if coeffs[i] == 1:
                term = SymbolicBit.const(1)
                if (i & 1): term = term * b0
                if (i & 2): term = term * b1
                if (i & 4): term = term * b2
                if (i & 8): term = term * b3
                y = y + term
        outputs.append(y)
    return [outputs[3], outputs[2], outputs[1], outputs[0]]

def gf_mul_2(nibble):
    b3, b2, b1, b0 = nibble
    return [b2, b1, b0 + b3, b3]

def gf_mul_3(nibble):
    m2 = gf_mul_2(nibble)
    return [m + n for m, n in zip(m2, nibble)]

def mix_columns(state):
    s0, s1, s2, s3 = state[0:4], state[4:8], state[8:12], state[12:16]
    c0 = [a+b for a,b in zip(gf_mul_2(s0), gf_mul_3(s2))]
    c1 = [a+b for a,b in zip(gf_mul_2(s1), gf_mul_3(s3))]
    c2 = [a+b for a,b in zip(gf_mul_3(s0), gf_mul_2(s2))]
    c3 = [a+b for a,b in zip(gf_mul_3(s1), gf_mul_2(s3))]
    return c0 + c1 + c2 + c3

def save_file(filename, title, state, limit_bits=None):
    filepath = os.path.join(OUTPUT_DIR, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(f"=== {title} ===\n\n")
        range_to_save = limit_bits if limit_bits else range(16)
        for i in range_to_save:
            bit_name = f"y_{15-i}" 
            full_eq = state[i].to_full_string()
            f.write(f"--- {bit_name} ---\n")
            f.write(full_eq)
            f.write("\n\n")

def run_analysis():
    print("ALGEBRAIC ANALYSIS TOOL (BabyAES)")
    print(f"Output directory: ./{OUTPUT_DIR}/")
    print("-" * 40)
    
    anf_coeffs = get_anf_coeffs(REAL_SBOX)
    
    state = [SymbolicBit.var(f"x_{{{15-i}}}") for i in range(16)]
    
    #ROUND 0
    sys.stdout.write("Round 0")
    sys.stdout.flush()
    for i in range(16):
        state[i] = state[i] + SymbolicBit.var(f"k_{{0}}_{{{15-i}}}")
    save_file("0_Round0_Start.txt", "ROUND 0 (AddRoundKey)", state)
    print("Done.")

    #ROUND 1
    sys.stdout.write("Round 1 (SubBytes, Shift, Mix)")
    sys.stdout.flush()
    
    #SubBytes
    temp = []
    for i in range(0, 16, 4):
        temp.extend(sbox_symbolic(state[i:i+4], anf_coeffs))
    state = temp
    save_file("1_Round1_SubBytes.txt", "Round 1: After SubBytes", state)
    
    #ShiftRows
    s0, s1, s2, s3 = state[0:4], state[4:8], state[8:12], state[12:16]
    state = s0 + s1 + s3 + s2
    save_file("2_Round1_ShiftRows.txt", "Round 1: After ShiftRows", state)
    
    #MixColumns
    state = mix_columns(state)
    save_file("3_Round1_MixColumns.txt", "Round 1: After MixColumns", state)
    
    #AddRoundKey
    for i in range(16):
        state[i] = state[i] + SymbolicBit.var(f"k_{{1}}_{{{15-i}}}")
    save_file("4_Round1_Final.txt", "Round 1: Final (After AddRoundKey)", state)

    #ROUND 2 (EXPLOSION)
    print("-" * 40)
    print("Round 2 (Complexity Explosion)")
    print("Target: Bit y_0")
    
    target_nibble = state[12:16]
    lsb_anf = anf_coeffs[0] 
    b3, b2, b1, b0 = target_nibble
    y0 = SymbolicBit()
    
    total_terms = sum(lsb_anf)
    processed = 0
    
    for i in range(16):
        if lsb_anf[i] == 1:
            term = SymbolicBit.const(1)
            if (i & 1): term = term * b0
            if (i & 2): term = term * b1
            if (i & 4): term = term * b2
            if (i & 8): term = term * b3
            y0 = y0 + term
            
            processed += 1
            percent = int((processed / total_terms) * 100)
            sys.stdout.write(f"\r    Progress: [{('=' * (percent // 10)).ljust(10)}] {percent}%")
            sys.stdout.flush()

    dummy_state = [SymbolicBit() for _ in range(16)]
    dummy_state[15] = y0
    save_file("5_Round2_SubBytes_EXPLOSION.txt", "Round 2: SubBytes (Bit y_0 ONLY)", dummy_state, limit_bits=[15])
    
    print("-" * 40)
    print("[SUCCESS] All analysis files generated successfully")

if __name__ == "__main__":
    run_analysis()