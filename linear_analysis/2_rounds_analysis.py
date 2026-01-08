#użycie masek na WYJŚCIE S-boxa (out_mask) z LAT
#poprawna odwrotność MixColumns bez modyfikacji BabyAES (prekomputacja mapy)
#scoring kandydata jako suma kwadratów skorelowanych sygnałów (sum of squares)
#generowanie top-K kandydatów na każdą pozycję i globalne sprawdzenie kombinacji
#asercje walidujące odwrotność MixColumns
#opcjonalny DEBUG do diagnostyki

#Parametry i heurystyki można dostosować (NUM_PAIRS, TOP_LAT_PAIRS, K_CANDIDATES, itp.)

from baby_aes import BabyAES
import random
import itertools
import math
from collections import defaultdict

NUM_ROUNDS = 2
NUM_PAIRS = 20000
MASTER_KEY = 0b1111011011110100
SEED = 42

TOP_LAT_PAIRS = 16
MAX_PLAINTEXT_MASK_WEIGHT = 3

#scoring / search params
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

#Precompute inverse of mix_columns using only public methods of aes_obj (no changes to BabyAES)
def make_inv_mix_columns(aes_obj):
    inv_map = {}
    #precompute mapping mix_columns(s) -> s for all 16-bit states
    for s in range(0x10000):
        m = aes_obj.mix_columns(s)
        inv_map[m] = s
    #sanity check: mapping should be bijection (size 65536)
    if len(inv_map) != 0x10000:
        raise RuntimeError("inv_mix precomputation failed: mix_columns is not bijective over 16-bit states")
    def inv_mix(state):
        #if state not in map, raise to catch unexpected cases
        if state not in inv_map:
            raise KeyError(f"inv_mix: state 0x{state:04X} not found in precomputed map")
        return inv_map[state]
    return inv_mix

#Cofnięcie ostatniej rundy + odwrócenie MixColumns rundy 0
def inv_last_round_state_from_ct_and_guess(ct, guess_round_key_16, aes_obj, inv_mix_func):
    #remove guessed RK1 (XOR)
    temp = ct ^ guess_round_key_16
    #inverse shift rows
    temp2 = aes_obj.inv_shift_rows(temp)
    #inverse subbytes
    prev = aes_obj.inv_sub_bytes(temp2)
    #Now prev is state AFTER MixColumns(round0) XOR RK0
    #remove RK0 (whitening added at end of round0)
    prev ^= aes_obj.round_keys[0]
    #inverse MixColumns for round0 (use precomputed inverse mapping)
    prev = inv_mix_func(prev)
    #Now prev is the state *before* MixColumns in round0, i.e. output of SubBytes(round0)
    return prev

def precompute_plain_bits(plaintexts, plaintext_masks):
    #plaintexts should already be whitened: plaintext ^ RK0
    table = {}
    for mask in plaintext_masks:
        par = [ (popcount(p & mask) & 1) for p in plaintexts ]
        table[mask] = pack_parities_to_int(par)
    return table

def precompute_out_bits_for_pos(aes_obj, ciphertexts, sbox_index, top_out_masks, inv_mix_func):
    shift_map = [0, 1, 3, 2]  #sbox 0->pos0, sbox1->pos1, sbox2->pos3, sbox3->pos2
    rk1_pos = shift_map[sbox_index]  #position (0..3) where RK1 nibble sits
    out_bits_map = {}
    #For performance, we can precompute prev states for each ciphertext for each kguess
    for kguess in range(16):
        guess_key16 = (kguess & 0xF) << ((3 - rk1_pos) * 4)
        nib_list = []
        for ct in ciphertexts:
            prev = inv_last_round_state_from_ct_and_guess(ct, guess_key16, aes_obj, inv_mix_func)
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
    #signed correlation in [-1,1] where 1 means perfect match, -1 means perfect mismatch
    return (matches - mismatches) / num_pairs

def score_candidates_sum_of_squares(out_bits_map, plain_bits_map, lat, num_pairs):
    #precompute weight per out_mask = max_abs_lat over in_mask
    out_mask_weights = {}
    for (in_mask, out_mask), bias in lat.items():
        out_mask_weights[out_mask] = max(out_mask_weights.get(out_mask, 0.0), abs(bias))
    scores = {k: 0.0 for k in range(16)}
    #iterate over all (kguess, out_mask)
    for (kguess, out_mask), out_packed in out_bits_map.items():
        w = out_mask_weights.get(out_mask, 1.0)
        for mask_plain, plain_packed in plain_bits_map.items():
            c = compute_signed_correlation(plain_packed, out_packed, num_pairs)
            scores[kguess] += (c * c) * w
    return scores

def top_k_from_scores(scores, k):
    #return list of (kguess, score) sorted desc
    items = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    return items[:k]

def analyze_position_candidates(pos, aes_obj, ciphertexts, top_out_masks, plain_bits_map, num_pairs, inv_mix_func, lat, k_candidates):
    out_bits_map = precompute_out_bits_for_pos(aes_obj, ciphertexts, pos, top_out_masks, inv_mix_func)
    scores = score_candidates_sum_of_squares(out_bits_map, plain_bits_map, lat, num_pairs)
    topk = top_k_from_scores(scores, k_candidates)
    #For diagnostics compute signed bias for topk candidates and best mask info
    detailed = []
    for kguess, sc in topk:
        #find best single mask pair (mask_out, mask_plain) that gives largest abs(c)
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
    #build list of candidate lists per position
    lists = [ [k for (k,_) in per_pos_topk[pos]] for pos in range(4) ]
    combos = list(itertools.product(*lists))
    best_combo = None
    best_combo_score = -math.inf
    #quick score: sum of individual scores (we have scores in per_pos_topk)
    pos_score_map = { pos: {k: s for (k,s) in per_pos_topk[pos]} for pos in range(4) }
    for combo in combos:
        #combo is tuple of 4 nibbles in S-box index order (pos 0..3)
        #compute RK1 16-bit value: nibble pos -> RK1 position = shift_map[pos]
        shift_map = [0,1,3,2]
        rk1 = 0
        for pos, nib in enumerate(combo):
            rk1_pos = shift_map[pos]
            rk1 |= (nib & 0xF) << ((3 - rk1_pos) * 4)
        #combined score as sum of per-position scores
        combo_score = sum(pos_score_map[pos].get(combo[pos], 0.0) for pos in range(4))
        if combo_score > best_combo_score:
            best_combo_score = combo_score
            best_combo = (rk1, combo_score, combo)
    #best_combo contains (rk1, score, tuple_of_nibbles)
    return best_combo

def attack_recover_round_key1(aes_obj, plaintexts_whitened, ciphertexts, top_out_masks, plaintext_masks, inv_mix_func, lat):
    plain_bits_map = precompute_plain_bits(plaintexts_whitened, plaintext_masks)
    N = len(plaintexts_whitened)

    per_pos_topk = {}
    per_pos_details = {}

    for pos in range(4):
        topk, detailed = analyze_position_candidates(pos, aes_obj, ciphertexts, top_out_masks, plain_bits_map, N, inv_mix_func, lat, K_CANDIDATES)
        per_pos_topk[pos] = topk
        per_pos_details[pos] = detailed
        if DEBUG:
            print(f"[DEBUG] pos {pos} topk: {topk}")
            for d in detailed:
                print(f"[DEBUG]   detail: {d}")

    #combine top-K candidates across positions
    best_combo = combine_candidates_and_select(aes_obj, plaintexts_whitened, ciphertexts, per_pos_topk, inv_mix_func)
    if best_combo is None:
        #fallback: choose best single candidate per pos
        recovered = 0
        shift_map = [0,1,3,2]
        for pos in range(4):
            best_k = per_pos_topk[pos][0][0] if per_pos_topk[pos] else 0
            rk1_pos = shift_map[pos]
            recovered |= (best_k & 0xF) << ((3 - rk1_pos) * 4)
        return recovered, per_pos_topk, per_pos_details
    recovered_rk1, score, combo = best_combo
    #also prepare readable per-position chosen nibble
    chosen_per_pos = { pos: combo[pos] for pos in range(4) }
    return recovered_rk1, per_pos_topk, per_pos_details

def main():
    aes = BabyAES(master_key=MASTER_KEY, num_rounds=NUM_ROUNDS, verbose=False)
    aes.round_keys = aes.key_expansion()

    plaintexts = []
    ciphertexts = []
    for _ in range(NUM_PAIRS):
        pt = random.getrandbits(16)
        ct = aes.encrypt(pt)
        plaintexts.append(pt ^ aes.round_keys[0])  #whitened plaintexts
        ciphertexts.append(ct)

    true_round_key1 = aes.round_keys[1]
    print(f"Prawdziwy round_key[1] = 0x{true_round_key1:04X}")

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

    recovered_key1, per_pos_topk, per_pos_details = attack_recover_round_key1(
        aes, plaintexts, ciphertexts, top_out_masks, plaintext_masks, inv_mix_func, lat
    )

    print(f"\nOdzyskany round_key[1] = 0x{recovered_key1:04X}")

    print("\nPorównanie nibble (MSB -> LSB):")
    for pos in range(4):
        true_n = (true_round_key1 >> ((3-pos)*4)) & 0xF
        rec_n = (recovered_key1 >> ((3-pos)*4)) & 0xF
        topk = per_pos_topk[pos]
        topk_str = ", ".join([f"{k:01X}({s:.3f})" for (k,s) in topk])
        #best single-candidate bias info if available
        best_info = per_pos_details[pos][0] if per_pos_details.get(pos) and len(per_pos_details[pos])>0 else None
        best_corr = best_info["best_corr"] if best_info else None
        print(f" pos {pos}: true=0x{true_n:X} rec=0x{rec_n:X} topk=[{topk_str}] best_corr={best_corr}")

if __name__ == "__main__":
    main()
