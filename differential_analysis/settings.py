DATA_DIR = "data"
# --- 2. KONFIGURACJA SZYFRU (BabyAES) ---
# Klucz główny używany przez "Ofiarę" (do generowania danych)
MASTER_KEY = 0b1010010110100101 

# Całkowita liczba rund szyfru (np. 2, 3, 4)
# To decyduje, jak głęboko szyfruje oracle.
TOTAL_CIPHER_ROUNDS = 2

# --- 3. KONFIGURACJA ŚCIEŻKI RÓŻNICOWEJ (Find Path) ---
# Ile rund ma obejmować nasza ścieżka różnicowa?
# Zazwyczaj: PATH_ROUNDS = TOTAL_CIPHER_ROUNDS - 1
# (bo ostatnią rundę atakujemy, więc ścieżka musi doprowadzić nas do jej drzwi)
PATH_ROUNDS = 1

# Różnica wejściowa, którą chcemy testować (możesz ją zmienić po analizie DDT)
# Domyślnie 0x000B (najlepsza dla BabyAES S-box)
INITIAL_DELTA_IN = 0x000B

# --- 4. KONFIGURACJA GENERATORA (Generate Data) ---
# Ile par szyfrogramów chcemy zebrać?
NUM_PAIRS = 500
# Nazwa kolekcji do zapisu
COLLECTION_NAME = "attack_data_run1"

# Inne stałe
BLOCK_SIZE = 16