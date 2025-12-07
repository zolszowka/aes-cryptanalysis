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

def recover_round_key(collection, expected_diff_full):
    """
    Główna logika ataku.
    1. Prostuje dane (InvShiftRows).
    2. Atakuje aktywne nibble metodą różnicową.
    3. Atakuje pasywne nibble metodą spójności (Consistency Check).
    """
    PathVisualizer.print_header(f"ATAK NA RUNDĘ {differential_analysis.settings.TOTAL_CIPHER_ROUNDS}")
    print(f"Cel (Target Diff): 0x{expected_diff_full:04X}\n")
    
    # --- KROK 1: Wstępne przetwarzanie danych (InvShiftRows) ---
    # Musimy "wyprostować" szyfrogramy, żeby atakować nibble niezależnie.
    # Robimy to raz dla wszystkich par, żeby nie liczyć tego w pętlach.
    print(f"[PRE-PROCESSING] Prostowanie {len(collection)} par (InvShiftRows)...")
    aligned_pairs = []
    
    for pair in collection:
        # Pobieramy wartości int z obiektów Block
        c1 = pair.m1.value
        c2 = pair.m2.value
        
        # Wykonujemy InvShiftRows na całych 16 bitach
        c1_aligned = aes_helper.inv_shift_rows(c1)
        c2_aligned = aes_helper.inv_shift_rows(c2)
        
        aligned_pairs.append((c1_aligned, c2_aligned))

    # Tablica na odzyskane fragmenty klucza (indeksy 0-3)
    recovered_key_nibbles = [None] * 4 
    
    # --- KROK 2: Faza Różnicowa (Active Nibbles) ---
    print("\n--- FAZA 1: ATAK RÓŻNICOWY (Aktywne Nibble) ---")
    
    for i in range(4):
        # Sprawdzamy, czy ten nibble ma być aktywny (czy diff > 0)
        shift = (3 - i) * 4
        expected_nibble_diff = (expected_diff_full >> shift) & 0xF
        
        if expected_nibble_diff != 0:
            best_k, score = solve_nibble(aligned_pairs, i, expected_nibble_diff)
            
            accuracy = (score / len(aligned_pairs)) * 100
            color = PathVisualizer.C_GREEN if accuracy > 30 else PathVisualizer.C_RED
            
            print(f"Nibble {i}: Oczekiwana różnica {expected_nibble_diff:X} -> "
                  f"{color}Zgadnięto Klucz: {best_k:X}{PathVisualizer.C_RESET} "
                  f"(Trafień: {score}/{len(aligned_pairs)})")
            
            recovered_key_nibbles[i] = best_k
        else:
            # Różnica 0 - metoda różnicowa słabo tu działa, zostawiamy na później
            print(f"Nibble {i}: Pasywny (różnica 0) -> Pomijam.")

    # --- KROK 3: Faza Spójności (Passive Nibbles) ---
    # Dla nibbli, gdzie różnica wynosi 0, szukamy klucza, który sprawia,
    # że po odszyfrowaniu faktycznie wychodzi różnica 0.
    
    print("\n--- FAZA 2: CHECK SPÓJNOŚCI (Pasywne Nibble) ---")
    
    for i in range(4):
        if recovered_key_nibbles[i] is None:
            shift = (3 - i) * 4
            print(f"Nibble {i}: Szukam metodą Bruteforce/Consistency...")
            
            best_k = -1
            best_consistency = -1
            
            # Sprawdzamy każdy możliwy klucz dla tego nibbla
            for k_guess in range(16):
                matches = 0
                for v1, v2 in aligned_pairs:
                    # Wyciągnij nibble
                    y1 = (v1 >> shift) & 0xF
                    y2 = (v2 >> shift) & 0xF
                    
                    # Cofnij
                    val1 = BabyAES.INV_SBOX[y1 ^ k_guess]
                    val2 = BabyAES.INV_SBOX[y2 ^ k_guess]
                    
                    # Sprawdź czy różnica to 0 (bo to nibble pasywny)
                    if (val1 ^ val2) == 0:
                        matches += 1
                
                if matches > best_consistency:
                    best_consistency = matches
                    best_k = k_guess
            
            print(f" -> Znaleziono: {PathVisualizer.C_YELLOW}{best_k:X}{PathVisualizer.C_RESET} "
                  f"(Zgodność: {best_consistency}/{len(aligned_pairs)})")
            recovered_key_nibbles[i] = best_k

    # --- KROK 4: Złożenie klucza ---
    # Składamy 4 nibble w jedną liczbę 16-bitową
    final_equivalent_key = 0
    for i in range(4):
        val = recovered_key_nibbles[i]
        shift = (3 - i) * 4
        final_equivalent_key |= (val << shift)

    print(f"\nOdzyskany Klucz Ekwiwalentny: 0x{final_equivalent_key:04X}")
    return final_equivalent_key

def run_attack(collection_id, target_diff):
    """
    Orkiestrator ataku wywoływany przez run_analysis.py
    """
    # 1. Wczytanie danych
    try:
        print(f"Wczytuję kolekcję: {collection_id}...")
        collection = DiffPairCollection.load(collection_id)
        print(f"Załadowano {len(collection)} par szyfrogramów.")
    except FileNotFoundError:
        print(f"{PathVisualizer.C_RED}Błąd: Nie znaleziono pliku kolekcji!{PathVisualizer.C_RESET}")
        return False

    # 2. Odzyskanie klucza ekwiwalentnego (RoundKey po InvShiftRows)
    equiv_key = recover_round_key(collection, target_diff)
    
    # 3. Transformacja do Prawdziwego Klucza Rundy
    # Odzyskaliśmy klucz dla danych "wyprostowanych" przez InvShiftRows.
    # Prawdziwy klucz był "krzywy". Żeby go dostać, musimy go "skrzywić" z powrotem (ShiftRows).
    real_round_key = aes_helper.shift_rows(equiv_key)
    
    print(f"\n{PathVisualizer.C_BOLD}--- REKONSTRUKCJA ---{PathVisualizer.C_RESET}")
    print(f"Prawdziwy Klucz Rundy {differential_analysis.settings.TOTAL_CIPHER_ROUNDS}: {PathVisualizer.C_CYAN}0x{real_round_key:04X}{PathVisualizer.C_RESET}")

    # 4. Reverse Key Schedule (Odzyskanie Master Key)
    # W BabyAES: RoundKey_i = (MK <<< 4*i)
    # Więc: MK = (RoundKey_i >>> 4*i)
    
    rk_index = differential_analysis.settings.TOTAL_CIPHER_ROUNDS
    # Rotacja w prawo o (4 * numer_rundy)
    rotation_bits = (4 * rk_index) % 16
    
    # Implementacja rotacji w prawo na 16 bitach:
    master_key_guess = ((real_round_key >> rotation_bits) | (real_round_key << (16 - rotation_bits))) & 0xFFFF
    
    # 5. Weryfikacja
    print(f"Odzyskany Master Key:   {PathVisualizer.C_BOLD}{PathVisualizer.C_GREEN}0x{master_key_guess:04X}{PathVisualizer.C_RESET}")
    print(f"Prawdziwy Master Key:   0x{differential_analysis.settings.MASTER_KEY:04X}")
    
    if master_key_guess == differential_analysis.settings.MASTER_KEY:
        return True
    else:
        return False
