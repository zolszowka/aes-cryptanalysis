#dostosowanie do 3 rund
#uogólniona inwersja ostatniej rundy (usuwa poprzedni RK o indeksie L-1)
#atak odzyskuje ostatni klucz rundy: round_keys[NUM_ROUNDS-1]

from baby_aes import BabyAES
import random
import itertools
import math
from collections import defaultdict

NUM_ROUNDS = 3
NUM_PAIRS = 20000
MASTER_KEY = 0b1111011011110100
SEED = 42

TOP_LAT_PAIRS = 16
MAX_PLAINTEXT_MASK_WEIGHT = 3

K_CANDIDATES = 3
DEBUG = False

random.seed(SEED)

def popcount(x: int) -> int:
    return x.bit_count() if hasattr(int, "bit_count") else bin(x).count("1")

def get_nibbles_from_state(state: int):
    return [ (state >> 12) & 0xF, (state >> 8) & 0xF, (state >> 4) & 0xF, state & 0xF ]

def build_sbox_lat(sbox):
    lat = {}
    for in_mask in range(1, 16):
        for out_mask in range(1, 16):
            matches = 0
            for x in range(16):
                y = sbox[x]
                in_par = popcount(x & in_mask) & 1
                out_par = popcount(y & out_mask) & 1
                if in_par == out_par:
                    matches += 1
            bias = (matches / 16) - 0.5
            lat[(in_mask, out_mask)] = bias
    return lat

def generate_plaintext_masks(max_weight):
    bits = list(range(16))
    masks = []
    for w in range(1, max_weight+1):
        for comb in itertools.combinations(bits, w):
            mask = 0
            for b in comb:
                mask |= 1 << (15 - b)
            masks.append(mask)
    return masks

def pack_parities_to_int(parity_list):
    bits = 0
    for b in parity_list:
        bits = (bits << 1) | (b & 1)
    return bits

#Odwracanie mix_columns
def make_inv_mix_columns(aes_obj):
    inv_map = {}
    for s in range(0x10000):
        m = aes_obj.mix_columns(s)
        inv_map[m] = s
    if len(inv_map) != 0x10000:
        raise RuntimeError("inv_mix precomputation failed: mix_columns is not bijective over 16-bit states")
    def inv_mix(state):
        if state not in inv_map:
            raise KeyError(f"inv_mix: state 0x{state:04X} not found in precomputed map")
        return inv_map[state]
    return inv_mix

#Cofnięcie ostatniej rundy + odwrócenie MixColumns poprzedniej rundy
#prev_rk_index - indeks klucza rundy, który należy usunąć przed odwróceniem MixColumns
def inv_last_round_state_from_ct_and_guess(ct, guess_round_key_16, aes_obj, inv_mix_func, prev_rk_index):
    #Usunięcie zgadniętego klucza ostatniej rundy
    temp = ct ^ guess_round_key_16
    #Odwrócenie shift_rows
    temp2 = aes_obj.inv_shift_rows(temp)
    #Odwrócenie subbytes
    prev = aes_obj.inv_sub_bytes(temp2)
    #Tutaj prev to stan po mixcolumns XOR rk_prev
    #Usunięcie RK_prev (kllucz ostatniej rundy)
    prev ^= aes_obj.round_keys[prev_rk_index]
    #Odwrócenie mixcolumns
    prev = inv_mix_func(prev)
    return prev

def precompute_plain_bits(plaintexts, plaintext_masks):
    table = {}
    for mask in plaintext_masks:
        par = [ (popcount(p & mask) & 1) for p in plaintexts ]
        table[mask] = pack_parities_to_int(par)
    return table

def precompute_out_bits_for_pos(aes_obj, ciphertexts, sbox_index, top_out_masks, inv_mix_func, prev_rk_index):
    shift_map = [0, 1, 3, 2]  #sbox 0->pos0, sbox1->pos1, sbox2->pos3, sbox3->pos2
    rk1_pos = shift_map[sbox_index]  #pozycja (0..3) gdzie jest nibble RK_last
    out_bits_map = {}
    for kguess in range(16):
        guess_key16 = (kguess & 0xF) << ((3 - rk1_pos) * 4)
        nib_list = []
        for ct in ciphertexts:
            prev = inv_last_round_state_from_ct_and_guess(ct, guess_key16, aes_obj, inv_mix_func, prev_rk_index)
            nib = get_nibbles_from_state(prev)[sbox_index]
            nib_list.append(nib)
        for mask_out in top_out_masks:
            par = [ (popcount(n & mask_out) & 1) for n in nib_list ]
            out_bits_map[(kguess, mask_out)] = pack_parities_to_int(par)
    return out_bits_map

def compute_signed_correlation(packed_a, packed_b, num_pairs):
    xor = packed_a ^ packed_b
    mismatches = popcount(xor)
    matches = num_pairs - mismatches
    #dla [-1,1] 1 oznacza idealne dopasowanie, a -1 means idealne niedopasowanie
    return (matches - mismatches) / num_pairs

def score_candidates_sum_of_squares(out_bits_map, plain_bits_map, lat, num_pairs):
    out_mask_weights = {}
    for (in_mask, out_mask), bias in lat.items():
        out_mask_weights[out_mask] = max(out_mask_weights.get(out_mask, 0.0), abs(bias))
    scores = {k: 0.0 for k in range(16)}
    for (kguess, out_mask), out_packed in out_bits_map.items():
        w = out_mask_weights.get(out_mask, 1.0)
        for mask_plain, plain_packed in plain_bits_map.items():
            c = compute_signed_correlation(plain_packed, out_packed, num_pairs)
            scores[kguess] += (c * c) * w
    return scores

def top_k_from_scores(scores, k):
    items = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    return items[:k]

def analyze_position_candidates(pos, aes_obj, ciphertexts, top_out_masks, plain_bits_map, num_pairs, inv_mix_func, lat, k_candidates, prev_rk_index):
    out_bits_map = precompute_out_bits_for_pos(aes_obj, ciphertexts, pos, top_out_masks, inv_mix_func, prev_rk_index)
    scores = score_candidates_sum_of_squares(out_bits_map, plain_bits_map, lat, num_pairs)
    topk = top_k_from_scores(scores, k_candidates)
    detailed = []
    for kguess, sc in topk:
        best = None
        best_abs = -1.0
        for (kg, mask_out), out_packed in out_bits_map.items():
            if kg != kguess:
                continue
            for mask_plain, plain_packed in plain_bits_map.items():
                c = compute_signed_correlation(plain_packed, out_packed, num_pairs)
                if abs(c) > best_abs:
                    best_abs = abs(c)
                    best = (mask_out, mask_plain, c)
        detailed.append({"kguess": kguess, "score": sc, "best_mask_out": best[0], "best_mask_plain": best[1], "best_corr": best[2]})
    return topk, detailed

def combine_candidates_and_select(aes_obj, plaintexts_whitened, ciphertexts, per_pos_topk, inv_mix_func):
    #lista kandydatów
    lists = [ [k for (k,_) in per_pos_topk[pos]] for pos in range(4) ]
    combos = list(itertools.product(*lists))
    best_combo = None
    best_combo_score = -math.inf
    #sumam indywidualnych wyników
    pos_score_map = { pos: {k: s for (k,s) in per_pos_topk[pos]} for pos in range(4) }
    for combo in combos:
        shift_map = [0,1,3,2]
        rk_last = 0
        for pos, nib in enumerate(combo):
            rk1_pos = shift_map[pos]
            rk_last |= (nib & 0xF) << ((3 - rk1_pos) * 4)
        combo_score = sum(pos_score_map[pos].get(combo[pos], 0.0) for pos in range(4))
        if combo_score > best_combo_score:
            best_combo_score = combo_score
            best_combo = (rk_last, combo_score, combo)
    return best_combo

def attack_recover_last_round_key(aes_obj, plaintexts_whitened, ciphertexts, top_out_masks, plaintext_masks, inv_mix_func, lat, num_pairs, k_candidates):
    plain_bits_map = precompute_plain_bits(plaintexts_whitened, plaintext_masks)
    N = len(plaintexts_whitened)

    per_pos_topk = {}
    per_pos_details = {}

    prev_rk_index = len(aes_obj.round_keys) - 2
    for pos in range(4):
        topk, detailed = analyze_position_candidates(pos, aes_obj, ciphertexts, top_out_masks, plain_bits_map, N, inv_mix_func, lat, k_candidates, prev_rk_index)
        per_pos_topk[pos] = topk
        per_pos_details[pos] = detailed
        if DEBUG:
            print(f"[DEBUG] pos {pos} topk: {topk}")
            for d in detailed:
                print(f"[DEBUG]   detail: {d}")

    best_combo = combine_candidates_and_select(aes_obj, plaintexts_whitened, ciphertexts, per_pos_topk, inv_mix_func)
    if best_combo is None:
        recovered = 0
        shift_map = [0,1,3,2]
        for pos in range(4):
            best_k = per_pos_topk[pos][0][0] if per_pos_topk[pos] else 0
            rk1_pos = shift_map[pos]
            recovered |= (best_k & 0xF) << ((3 - rk1_pos) * 4)
        return recovered, per_pos_topk, per_pos_details
    recovered_rk_last, score, combo = best_combo
    chosen_per_pos = { pos: combo[pos] for pos in range(4) }
    return recovered_rk_last, per_pos_topk, per_pos_details

def main():
    aes = BabyAES(master_key=MASTER_KEY, num_rounds=NUM_ROUNDS, verbose=False)
    aes.round_keys = aes.key_expansion()

    plaintexts = []
    ciphertexts = []
    for _ in range(NUM_PAIRS):
        pt = random.getrandbits(16)
        ct = aes.encrypt(pt)
        plaintexts.append(pt ^ aes.round_keys[0])
        ciphertexts.append(ct)

    true_last_round_key = aes.round_keys[NUM_ROUNDS-1]
    print(f"Prawdziwy round_key[{NUM_ROUNDS-1}] = 0x{true_last_round_key:04X}")

    lat = build_sbox_lat(aes.SBOX)
    sorted_pairs = sorted(lat.items(), key=lambda kv: abs(kv[1]), reverse=True)
    top_pairs = sorted_pairs[:TOP_LAT_PAIRS]
    top_out_masks = []
    for (in_mask, out_mask), bias in top_pairs:
        if out_mask not in top_out_masks:
            top_out_masks.append(out_mask)
    if not top_out_masks:
        top_out_masks = list(range(1,16))
    print(f"Top out_masks: {top_out_masks}")

    plaintext_masks = generate_plaintext_masks(MAX_PLAINTEXT_MASK_WEIGHT)
    print(f"Liczba masek plaintextu: {len(plaintext_masks)}")

    print("Start ataku...")

    inv_mix_func = make_inv_mix_columns(aes)
    for _ in range(10):
        s = random.getrandbits(16)
        assert inv_mix_func(aes.mix_columns(s)) == s

    recovered_key_last, per_pos_topk, per_pos_details = attack_recover_last_round_key(
        aes, plaintexts, ciphertexts, top_out_masks, plaintext_masks, inv_mix_func, lat, len(plaintexts), K_CANDIDATES
    )

    print(f"\nOdzyskany round_key[{NUM_ROUNDS-1}] = 0x{recovered_key_last:04X}")

    print("\nPorównanie nibble (MSB -> LSB):")
    for pos in range(4):
        true_n = (true_last_round_key >> ((3-pos)*4)) & 0xF
        rec_n = (recovered_key_last >> ((3-pos)*4)) & 0xF
        topk = per_pos_topk[pos]
        topk_str = ", ".join([f"{k:01X}({s:.3f})" for (k,s) in topk])
        best_info = per_pos_details[pos][0] if per_pos_details.get(pos) and len(per_pos_details[pos])>0 else None
        best_corr = best_info["best_corr"] if best_info else None
        print(f" pos {pos}: true=0x{true_n:X} rec=0x{rec_n:X} topk=[{topk_str}] best_corr={best_corr}")

if __name__ == "__main__":
    main()
