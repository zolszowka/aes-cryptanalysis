
import time

# Importujemy nasze moduły jako biblioteki
from differential_analysis.scripts.find_path import find_generic_path
from differential_analysis.scripts.generate_pairs import run_generation
from differential_analysis.scripts.attack import run_attack
from differential_analysis.utils.visualizer import PathVisualizer

def main():
    PathVisualizer.print_header("AUTOMATYCZNA KRYPTOANALIZA RÓŻNICOWA")
    
    start_time = time.time()

    # --- KROK 1: ZNAJDOWANIE ŚCIEŻKI ---
    print("\n[KROK 1] Analiza algorytmu i szukanie ścieżki różnicowej...")
    delta_in, expected_diff = find_generic_path(visualize=True)
    
    print(f"\n>>> ZNALEZIONO PARAMETRY:")
    print(f"    Najlepsza Różnica Wejściowa (Delta): 0x{delta_in:04X}")
    print(f"    Oczekiwana Różnica (Target):         0x{expected_diff:04X}")
    
    input("\nNaciśnij ENTER, aby rozpocząć generowanie danych...")

    # --- KROK 2: GENEROWANIE DANYCH (ONLINE PHASE) ---
    print("\n[KROK 2] Generowanie par szyfrogramów (Faza Online)...")
    
    # Przekazujemy wykrytą deltę do generatora
    collection_id = run_generation(override_delta_in=delta_in)
    
    print(f">>> DANE GOTOWE. ID Kolekcji: {collection_id}")
    
    # --- KROK 3: ATAK (OFFLINE PHASE) ---
    print("\n[KROK 3] Uruchamianie ataku (Faza Offline)...")
    
    # Przekazujemy ID kolekcji i wyliczony cel do ataku
    success = run_attack(collection_id, expected_diff)

    end_time = time.time()
    duration = end_time - start_time

    PathVisualizer.print_header("RAPORT KOŃCOWY")
    if success:
        print(f"{PathVisualizer.C_GREEN}REZULTAT: SUKCES (Szyfr Złamany){PathVisualizer.C_RESET}")
    else:
        print(f"{PathVisualizer.C_RED}REZULTAT: PORAŻKA (Klucz nieodnaleziony){PathVisualizer.C_RESET}")
    
    print(f"Czas trwania: {duration:.2f} sek")

if __name__ == "__main__":
    main()