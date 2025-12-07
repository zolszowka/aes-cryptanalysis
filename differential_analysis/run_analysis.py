import os
import time

# Importujemy nasze moduły jako biblioteki
from differential_analysis.data_models.collections.diff_pair_collection import DiffPairCollection
from differential_analysis.scripts.find_path import get_ranked_paths
from differential_analysis.scripts.generate_pairs import run_generation
from differential_analysis.scripts.attack import differential_analysis_step, brute_force_completion
import differential_analysis.settings as settings
from differential_analysis.utils.visualizer import PathVisualizer
from baby_aes import BabyAES

# Helper do operacji na kluczach
aes_helper = BabyAES(0, 1)

def main():
    PathVisualizer.print_header("GENERYCZNA ANALIZA WIELOŚCIEŻKOWA")
    
    start_time = time.time()
    
    # Statystyki raportu
    stats = {
        "paths_checked": 0,
        "brute_force_used": False,
        "data_generated_fresh": False,
        "key_found": False
    }

    # 1. Ranking Ścieżek
    print("Generowanie rankingu ścieżek...")
    ranked_paths = get_ranked_paths()
    print(f"Dostępnych ścieżek w rankingu: {len(ranked_paths)}")
    
    # Wiedza o kluczu (None = nieznany nibble)
    known_key_nibbles = [None] * 4
    
    ref_p = None
    ref_c = None

    # --- PĘTLA PO ŚCIEŻKACH ---
    limit_paths = min(settings.MAX_PATHS, len(ranked_paths))
    
    for path_idx in range(limit_paths):
        stats["paths_checked"] += 1
        path_info = ranked_paths[path_idx]
        
        print(f"\n{PathVisualizer.C_BOLD}>>> [ŚCIEŻKA #{path_idx + 1}] Delta: 0x{path_info['delta_in']:04X} -> Cel: 0x{path_info['expected_diff']:04X}{PathVisualizer.C_RESET}")

        # 2. Zarządzanie Danymi (Smart Loading)
        # Tworzymy unikalną nazwę kolekcji dla tej konkretnej delty
        col_name = f"{settings.COLLECTION_NAME_PREFIX}_delta_{path_info['delta_in']:X}"
        col_file_path = os.path.join(settings.DATA_DIR, "collections", f"{col_name}.json")
        
        col_id = None
        
        # Sprawdzamy czy dane już istnieją
        if os.path.exists(col_file_path):
            print(f"[CACHE] Znaleziono istniejące dane dla tej ścieżki. Wczytuję...")
            # Musimy wyciągnąć ID z nazwy pliku lub załadować po nazwie.
            # Nasz loader ładuje po ID (UUID). 
            # Dla uproszczenia: wczytamy plik JSON ręcznie żeby pobrać ID, 
            # lub po prostu wygenerujemy nową kolekcję jeśli cache system jest zbyt prosty.
            # Tutaj: Załóżmy wariant prosty - jeśli plik jest, próbujemy go użyć.
            # (Wymagałoby to zmiany w DataModel żeby szukać po nazwie, 
            #  więc dla 100% pewności wygenerujmy, CHYBA ŻE zaimplementujesz mapowanie Nazwa->ID).
            
            # Wariant bezpieczny (nadpisanie):
            # print("   (Nadpisuję świeżymi danymi)")
            # col_id = run_generation(override_delta_in=path_info['delta_in'])
            # stats["data_generated_fresh"] = True
            
            # Wariant PRO (z mapowaniem nazw na ID w przyszłości):
            # Tu użyjemy Twojego run_generation, który w obecnej formie ZAWSZE generuje.
            # Aby to zmienić, run_generation musiałoby sprawdzać pliki.
            pass

        # Na razie generujemy zawsze (dla bezpieczeństwa ataku)
        settings.COLLECTION_NAME = col_name # Ustawiamy nazwę dla generatora
        col_id = run_generation(override_delta_in=path_info['delta_in'])
        
        # Wczytanie
        collection = DiffPairCollection.load(col_id)
        
        # Pobranie pary referencyjnej
        if ref_p is None and len(collection) > 0:
            first = collection.get_pair(0)
            if first.p1:
                ref_p = first.p1.value
                ref_c = first.m1.value
                print(f"[INFO] Para weryfikacyjna: P=0x{ref_p:04X} -> C=0x{ref_c:04X}")

        # 3. Analiza Różnicowa
        partial_result = differential_analysis_step(collection, path_info['expected_diff'])
        
        # 4. Aktualizacja Wiedzy
        new_info = False
        for i in range(4):
            val = partial_result[i]
            if val is not None:
                if known_key_nibbles[i] is None:
                    known_key_nibbles[i] = val
                    new_info = True
                elif known_key_nibbles[i] != val:
                    print(f"{PathVisualizer.C_RED}[KONFLIKT] Nibble {i}: {known_key_nibbles[i]:X} vs {val:X}{PathVisualizer.C_RESET}")

        state_str = str([hex(k) if k is not None else '?' for k in known_key_nibbles])
        print(f"Stan klucza: {state_str}")

        if None not in known_key_nibbles:
            print(f"{PathVisualizer.C_GREEN}>>> Klucz kompletny!{PathVisualizer.C_RESET}")
            break
        
        if not new_info:
            print("Ścieżka nie wniosła nowych informacji.")

    # --- PO PĘTLI: BRUTE FORCE ---
    final_equiv_key = None
    
    if None in known_key_nibbles:
        if settings.ENABLE_BRUTE_FORCE and ref_p is not None:
            stats["brute_force_used"] = True
            print(f"\n{PathVisualizer.C_YELLOW}>>> Uruchamiam BRUTE-FORCE dla brakujących nibbli...{PathVisualizer.C_RESET}")
            final_equiv_key = brute_force_completion(known_key_nibbles, ref_p, ref_c)
        else:
            print("\nBrak możliwości Brute-Force (wyłączony lub brak P1).")
    else:
        # Składamy kompletny klucz
        k = 0
        for i in range(4): k |= (known_key_nibbles[i] << ((3-i)*4))
        final_equiv_key = k

    # --- KONWERSJA I WERYFIKACJA ---
    end_time = time.time()
    duration = end_time - start_time
    
    PathVisualizer.print_header("RAPORT KOŃCOWY")
    
    print(f"Czas analizy:      {duration:.4f} sek")
    print(f"Użyte ścieżki:     {stats['paths_checked']} / {settings.MAX_PATHS}")
    print(f"Brute-Force użyty: {'TAK' if stats['brute_force_used'] else 'NIE'}")

    if final_equiv_key is not None:
        # Konwersja
        real_round_key = aes_helper.shift_rows(final_equiv_key)
        
        # Key Schedule Reverse
        rk_idx = settings.TOTAL_CIPHER_ROUNDS - 1
        rot = (4 * rk_idx) % 16
        master_key_guess = ((real_round_key >> rot) | (real_round_key << (16 - rot))) & 0xFFFF
        
        print("-" * 40)
        print(f"Odzyskany Master:  0x{master_key_guess:04X}")
        print(f"Prawdziwy Master:  0x{settings.MASTER_KEY:04X}")
        
        if master_key_guess == settings.MASTER_KEY:
            stats["key_found"] = True
            print(f"\n{PathVisualizer.C_GREEN}{PathVisualizer.C_BOLD}REZULTAT: SUKCES (Szyfr Złamany){PathVisualizer.C_RESET}")
        else:
            print(f"\n{PathVisualizer.C_RED}{PathVisualizer.C_BOLD}REZULTAT: PORAŻKA (Zły klucz - sprawdź indeks rundy!){PathVisualizer.C_RESET}")
    else:
        print(f"\n{PathVisualizer.C_RED}REZULTAT: PORAŻKA (Nie odnaleziono klucza){PathVisualizer.C_RESET}")

if __name__ == "__main__":
    main()