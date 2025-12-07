from baby_aes import BabyAES
from differential_analysis.ddt_handler import DDTHandler
from differential_analysis.utils.visualizer import PathVisualizer
import differential_analysis.settings

def find_generic_path(visualize=True):
    if visualize:
        PathVisualizer.print_header(f"ANALIZA ŚCIEŻKI ({differential_analysis.settings.PATH_ROUNDS} RUND)")
    
    # Inicjalizacja
    aes = BabyAES(master_key=0, num_rounds=differential_analysis.settings.TOTAL_CIPHER_ROUNDS)
    ddt_handler = DDTHandler(BabyAES.SBOX) # <--- Instancja Handlera
    
    # Jeśli użytkownik nie podał delty w settings (0), znajdujemy najlepszą automatycznie
    current_diff = differential_analysis.settings.INITIAL_DELTA_IN
    if current_diff == 0:
         best_in, _, _ = ddt_handler.find_global_best_transition()
         current_diff = best_in # Dla S-boxa, trzeba to przesunąć na odpowiedni nibble
         # Dla uproszczenia w BabyAES, wstawiamy to na ostatni nibble
         current_diff = best_in # np. 0xB -> 0x000B (bo to int)
    
    total_prob = 1.0
    
    if visualize:
        # Pokaż DDT raz na początku
        ddt_handler.visualize()
        print(f"\nStartowa Różnica: 0x{current_diff:04X}\n")

    # --- PĘTLA PO RUNDACH ---
    for r in range(differential_analysis.settings.PATH_ROUNDS):
        if visualize:
            print(f"{PathVisualizer.C_BOLD}--- RUNDA {r + 1} ---{PathVisualizer.C_RESET}")
        
        # 1. WARSTWA S-BOX (Używamy Handlera)
        next_sbox_state = 0
        round_prob = 1.0
        
        for i in range(4): 
            shift = (3 - i) * 4
            nibble_in = (current_diff >> shift) & 0xF
            
            # UŻYCIE HANDLERA:
            nibble_out, p = ddt_handler.get_best_transition(nibble_in)
            
            next_sbox_state |= (nibble_out << shift)
            round_prob *= p 

        total_prob *= round_prob
        
        if visualize:
            print(f" S-Box Layer Out: 0x{next_sbox_state:04X} (Prob: {round_prob*100:.1f}%)")

        # 2. WARSTWA LINIOWA
        after_shift = aes.shift_rows(next_sbox_state)
        after_mix = aes.mix_columns(after_shift)
        
        if visualize and r == 0:
            step_data = {
                'input': current_diff,
                'sbox_out': next_sbox_state,
                'shift_out': after_shift,
                'mix_out': after_mix,
                'prob': round_prob * 100
            }
            PathVisualizer.visualize_path_step_by_step(step_data)
        elif visualize:
             print(f" Linear Layer Out: 0x{after_mix:04X}")

        current_diff = after_mix

    if visualize:
        PathVisualizer.print_header("WYNIK ANALIZY")
        print(f"DELTA_IN:      0x{differential_analysis.settings.INITIAL_DELTA_IN:04X}")
        print(f"EXPECTED_DIFF: 0x{current_diff:04X}")
    
    return differential_analysis.settings.INITIAL_DELTA_IN, current_diff

if __name__ == "__main__":
    find_generic_path()