from baby_aes import BabyAES
from differential_analysis.ddt_handler import DDTHandler
import differential_analysis.settings as settings

def get_ranked_paths():
    """
    Znajduje najlepsze ścieżki różnicowe dla całego szyfru.
    1. Pobiera najlepsze przejścia dla pojedynczego S-boxa z DDTHandler.
    2. Testuje każde z nich na każdej z 4 pozycji nibbli w bloku 16-bitowym.
    3. Symuluje propagację przez zadaną liczbę rund.
    
    Returns:
        List[dict]: Lista posortowanych ścieżek {'delta_in', 'expected_diff', 'prob'}
    """
    
    # Inicjalizacja narzędzi
    aes = BabyAES(master_key=0, num_rounds=settings.TOTAL_CIPHER_ROUNDS)
    ddt_handler = DDTHandler(BabyAES.SBOX)
    
    # 1. Pobierz najlepsze "cegiełki" (przejścia S-boxa)
    sbox_transitions = ddt_handler.get_ranked_sbox_transitions()
    
    full_paths = []

    # 2. Generuj kandydatów na pełne ścieżki
    # Dla każdego dobrego przejścia S-boxa...
    for sbox_in, sbox_out, base_prob in sbox_transitions:
        
        # ...sprawdź umieszczenie go w każdym z 4 nibbli bloku
        for nibble_idx in range(4):
            shift = (3 - nibble_idx) * 4
            
            # Tworzymy 16-bitową różnicę startową (np. 0x000B)
            current_diff = (sbox_in << shift)
            start_delta_in = current_diff
            
            total_path_prob = 1.0
            
            # 3. Symulacja propagacji przez rundy (PATH_ROUNDS)
            for r in range(settings.PATH_ROUNDS):
                next_round_input = 0
                round_prob = 1.0
                
                # A. Warstwa S-box (Nieliniowa)
                # Musimy sprawdzić każdy z 4 nibbli, bo po MixColumns w rundzie 1
                # w rundzie 2 mogą być aktywne 2, 3 lub 4 S-boxy!
                sbox_layer_out = 0
                
                for i in range(4):
                    chk_shift = (3 - i) * 4
                    nibble_val = (current_diff >> chk_shift) & 0xF
                    
                    # Pytamy Handlera o najlepsze wyjście dla tego nibbla
                    # (Jeśli nibble_val == 0, handler zwróci 0 i prob 1.0)
                    n_out, p = ddt_handler.get_best_transition(nibble_val)
                    
                    sbox_layer_out |= (n_out << chk_shift)
                    round_prob *= p
                
                total_path_prob *= round_prob
                
                # B. Warstwa Liniowa (ShiftRows + MixColumns)
                after_shift = aes.shift_rows(sbox_layer_out)
                after_mix = aes.mix_columns(after_shift)
                
                # Wynik tej rundy staje się wejściem następnej
                current_diff = after_mix

            # 4. Zapisujemy wynik symulacji
            # Ignorujemy ścieżki z zerowym prawdopodobieństwem (niemożliwe)
            if total_path_prob > 0.0:
                full_paths.append({
                    'delta_in': start_delta_in,      # To podasz do generatora
                    'expected_diff': current_diff,   # To podasz do attack.py
                    'prob': total_path_prob          # To służy do rankingu
                })

    # 5. Sortowanie globalne (najlepsze na górze)
    full_paths.sort(key=lambda x: x['prob'], reverse=True)
    
    return full_paths

if __name__ == "__main__":
    # Test bezpośredni
    ranked = get_ranked_paths()
    print(f"Znaleziono {len(ranked)} ścieżek.")
    for i, p in enumerate(ranked[:5]):
        print(f"{i+1}. In: 0x{p['delta_in']:04X} -> Target: 0x{p['expected_diff']:04X} (P: {p['prob']*100:.2f}%)")