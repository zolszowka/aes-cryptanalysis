import itertools

from baby_aes import BabyAES
from differential_analysis.data_models.collections.diff_pair_collection import DiffPairCollection
from differential_analysis.utils.visualizer import PathVisualizer
import differential_analysis.settings as settings

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
            # Próg wiarygodności ustawiany ręcznie w settingsacj
            accuracy = (score / len(aligned_pairs)) * 100
            if accuracy > settings.MIN_NIBBLE_ACCURACY_THRESHOLD: 
                print(f" -> Nibble {i}: Zgadnięto {best_k:X} ({accuracy:.1f}%)")
                recovered_parts[i] = best_k
            else:
                print(f" -> Nibble {i}: Wynik niepewny ({accuracy:.1f}%), odrzucam.")
        else:
            # Pasywny nibble - tu nie zgadujemy
            pass
            
    return recovered_parts

def brute_force_completion(partial_key_nibbles, collection):
    """
    Domyka brakujące (None) nibble metodą brute-force.
    Weryfikuje kandydata na KILKU parach P->C, aby uniknąć kolizji (False Positives).
    
    Args:
        partial_key_nibbles: Lista [k0, k1, k2, k3] z wynikami analizy różnicowej (lub None).
        collection: Obiekt DiffPairCollection z danymi.
        
    Returns:
        int: PEŁNY KLUCZ EKWIWALENTNY (przed ShiftRows) lub None.
    """
    print(f"\n[Brute-Force] Uzupełnianie brakujących fragmentów...")

    # 1. Sprawdzenie, czy klucz już jest kompletny
    missing_indices = [i for i, k in enumerate(partial_key_nibbles) if k is None]
    if not missing_indices:
        print("Klucz jest już kompletny!")
        k = 0
        for i in range(4): k |= (partial_key_nibbles[i] << ((3-i)*4))
        return k

    # 2. Przygotowanie par weryfikacyjnych (P -> C)
    # Pobieramy do 3 par, aby mieć pewność, że klucz jest poprawny.
    # Jedna para to za mało dla bloku 16-bit (ryzyko kolizji).
    pairs_to_check = []
    
    # Przeszukujemy kolekcję, aby znaleźć pary zawierające P1
    for i in range(len(collection)):
        pair = collection.get_pair(i)
        if pair.p1:
            # Zapisz tuple: (TekstJawny, Szyfrogram1)
            pairs_to_check.append((pair.p1.value, pair.m1.value))
            if len(pairs_to_check) >= 3:
                break
    
    if not pairs_to_check:
        print(f"{PathVisualizer.C_RED}BŁĄD: Brak par z tekstem jawnym (P1) w kolekcji!{PathVisualizer.C_RESET}")
        return None

    print(f"Brakuje nibbli: {missing_indices}. Weryfikacja na {len(pairs_to_check)} parach...")

    # 3. Generowanie zakresów do Brute-Force
    ranges = []
    for i in range(4):
        if partial_key_nibbles[i] is not None:
            ranges.append([partial_key_nibbles[i]]) # Sztywna wartość (już znana)
        else:
            ranges.append(range(16)) # Zgadujemy (0-15)

    # 4. Pętla sprawdzająca kombinacje
    for combination in itertools.product(*ranges):
        # Składamy kandydata na klucz ekwiwalentny
        candidate_equiv = 0
        for i in range(4):
            candidate_equiv |= (combination[i] << ((3-i)*4))
            
        # Konwersja na Prawdziwy Klucz Rundy (ShiftRows)
        candidate_round = aes_helper.shift_rows(candidate_equiv)
        
        # Reverse Key Schedule (Odzyskanie Master Key)
        rk_idx = settings.TOTAL_CIPHER_ROUNDS - 1
        rot = (4 * rk_idx) % 16
        
        # Rotacja w prawo - odwrócenie harmonogramu
        candidate_master = ((candidate_round >> rot) | (candidate_round << (16 - rot))) & 0xFFFF
        
        # Weryfikacja
        test_aes = BabyAES(master_key=candidate_master, num_rounds=settings.TOTAL_CIPHER_ROUNDS)
        
        all_match = True
        for (p_test, c_test) in pairs_to_check:
            if test_aes.encrypt(p_test) != c_test:
                all_match = False
                break # Jeśli chociaż jedna para nie pasuje, to zły klucz
        
        if all_match:
            print(f" -> {PathVisualizer.C_GREEN}ZNALEZIONO! Uzupełnienie: {combination}{PathVisualizer.C_RESET}")
            return candidate_equiv

    print("Nie znaleziono pasującego klucza w brute-force.")
    return None