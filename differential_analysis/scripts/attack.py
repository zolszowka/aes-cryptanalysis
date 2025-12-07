import itertools

from baby_aes import BabyAES
from differential_analysis.data_models.collections.diff_pair_collection import DiffPairCollection
from differential_analysis.utils.visualizer import PathVisualizer
import differential_analysis.settings

# Pomocnicza instancja do funkcji matematycznych (bez klucza)
aes_helper = BabyAES(master_key=0, num_rounds=1)

def solve_nibble(aligned_pairs, nibble_index, expected_diff_val):
    """
    Wykonuje atak różnicowy na JEDEN konkretny nibble.
    aligned_pairs: lista krotek (int, int) po InvShiftRows
    """
    scores = [0] * 16
    
    # Przesunięcie bitowe dla danego nibbla (np. nibble 0 -> shift 12)
    shift = (3 - nibble_index) * 4
    
    for k_guess in range(16):
        for c1_val, c2_val in aligned_pairs:
            
            # 1. Wyciągamy tylko interesujący nas nibble z "wyprostowanych" szyfrogramów
            y1 = (c1_val >> shift) & 0xF
            y2 = (c2_val >> shift) & 0xF
            
            # 2. Cofamy dodawanie klucza (XOR)
            x1 = y1 ^ k_guess
            x2 = y2 ^ k_guess
            
            # 3. Cofamy S-box (korzystając z tablicy w klasie BabyAES)
            val1 = BabyAES.INV_SBOX[x1]
            val2 = BabyAES.INV_SBOX[x2]
            
            # 4. Sprawdzamy różnicę
            diff = val1 ^ val2
            
            if diff == expected_diff_val:
                scores[k_guess] += 1
                
    # Znajdź najlepszy wynik
    best_score = max(scores)
    best_k = scores.index(best_score)
    
    return best_k, best_score

def differential_analysis_step(collection, expected_diff_full):
    """
    Wykonuje TYLKO część różnicową. 
    Zwraca listę [k0, k1, k2, k3], gdzie nieznane to None.
    """
    print(f"Analiza różnicowa dla celu: 0x{expected_diff_full:04X}")
    
    # Pre-processing (InvShiftRows)
    aligned_pairs = []
    for pair in collection:
        c1_aligned = aes_helper.inv_shift_rows(pair.m1.value)
        c2_aligned = aes_helper.inv_shift_rows(pair.m2.value)
        aligned_pairs.append((c1_aligned, c2_aligned))

    recovered_parts = [None] * 4
    
    for i in range(4):
        shift = (3 - i) * 4
        expected_nibble_diff = (expected_diff_full >> shift) & 0xF
        
        if expected_nibble_diff != 0:
            best_k, score = solve_nibble(aligned_pairs, i, expected_nibble_diff)
            # Prosty próg wiarygodności (np. 30%)
            accuracy = (score / len(aligned_pairs)) * 100
            if accuracy > 20: 
                print(f" -> Nibble {i}: Zgadnięto {best_k:X} ({accuracy:.1f}%)")
                recovered_parts[i] = best_k
            else:
                print(f" -> Nibble {i}: Wynik niepewny ({accuracy:.1f}%), odrzucam.")
        else:
            # Pasywny nibble - tu nie zgadujemy
            pass
            
    return recovered_parts

def brute_force_completion(partial_key_nibbles, p_val, c_val):
    """
    Domyka brakujące (None) nibble metodą brute-force na parze P-C.
    Zwraca PEŁNY KLUCZ EKWIWALENTNY lub None.
    """
    print(f"\n[Brute-Force] Uzupełnianie brakujących fragmentów...")
    
    missing_indices = [i for i, k in enumerate(partial_key_nibbles) if k is None]
    if not missing_indices:
        print("Klucz jest już kompletny!")
        # Składamy klucz
        k = 0
        for i in range(4): k |= (partial_key_nibbles[i] << ((3-i)*4))
        return k

    print(f"Brakuje nibbli: {missing_indices}. Sprawdzanie kombinacji...")
    
    ranges = []
    for i in range(4):
        if partial_key_nibbles[i] is not None:
            ranges.append([partial_key_nibbles[i]])
        else:
            ranges.append(range(16))

    for combination in itertools.product(*ranges):
        candidate_equiv = 0
        for i in range(4):
            candidate_equiv |= (combination[i] << ((3-i)*4))
            
        # Konwersja na Master Key do testu
        candidate_round = aes_helper.shift_rows(candidate_equiv)
        
        # Reverse Key Schedule
        rk_idx = differential_analysis.settings.TOTAL_CIPHER_ROUNDS - 1
        rot = (4 * rk_idx) % 16
        candidate_master = ((candidate_round >> rot) | (candidate_round << (16 - rot))) & 0xFFFF
        
        test_aes = BabyAES(master_key=candidate_master, num_rounds=differential_analysis.settings.TOTAL_CIPHER_ROUNDS)
        if test_aes.encrypt(p_val) == c_val:
            print(f" -> ZNALEZIONO! Uzupełnienie: {combination}")
            return candidate_equiv

    return None