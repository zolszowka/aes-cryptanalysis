DATA_DIR = "data"

# Klucz główny - do zgadywania
MASTER_KEY = 0b1110010111000110 

TOTAL_CIPHER_ROUNDS = 2

# Domyślna różnica wejściowa dla danych, w praktyce nie używana przez główny skrypt
INITIAL_DELTA_IN = 0x000B

# Liczba par szyfrogramów
NUM_PAIRS = 500

# Nazwa kolekcji do zapisu
COLLECTION_NAME_PREFIX = "attack_data_run1"

BLOCK_SIZE = 16

# Maksymalna liczba różnych ścieżek różnicowych do sprawdzenia
MAX_PATHS = 4

# Brute force dopiero po wyczerpaniu ścieżek w ilości MAX_PATHS
ENABLE_BRUTE_FORCE = True

# Powyżej niego uzna że nibble odgadnięty. Im bardziej powyżej 6.25 dla naszego baby aes, tym lepiej
MIN_NIBBLE_ACCURACY_THRESHOLD = 10.0

