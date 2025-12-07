from baby_aes import BabyAES
from differential_analysis.data_models.block import Block
from differential_analysis.data_models.diff_pair import DiffPair
from differential_analysis.data_models.collections.diff_pair_collection import DiffPairCollection
from differential_analysis.utils.data_generation_utils import generate_random_pair
import differential_analysis.settings

def run_generation(override_delta_in=None, override_count=None):
    
    # Używamy wartości z argumentów (w praktyce zawsze), jak nie to pobiera wartość z settings jakby ktoś
    # chciał to robić ręcznie
    delta_in = override_delta_in if override_delta_in is not None else differential_analysis.settings.INITIAL_DELTA_IN
    count = override_count if override_count is not None else differential_analysis.settings.NUM_PAIRS
    
    print(f"--- GENEROWANIE DANYCH ---")
    print(f"Delta In: 0x{delta_in:04X}")
    
    oracle = BabyAES(differential_analysis.settings.MASTER_KEY, differential_analysis.settings.TOTAL_CIPHER_ROUNDS)
    ct_collection = DiffPairCollection(name=differential_analysis.settings.COLLECTION_NAME)

    for i in range(count):
        # 1. Mamy parę tekstów jawnych (Plaintexts)
        pt_pair = generate_random_pair(delta_in, differential_analysis.settings.BLOCK_SIZE)

        # 2. Szyfrujemy
        c1 = oracle.encrypt(pt_pair.m1.value)
        c2 = oracle.encrypt(pt_pair.m2.value)

        # 3. Tworzymy parę Szyfrogramów
        # ZMIANA: Przekazujemy pt_pair.m1 jako trzeci argument (p1)
        ct_pair = DiffPair(
            m1=Block(c1, differential_analysis.settings.BLOCK_SIZE), 
            m2=Block(c2, differential_analysis.settings.BLOCK_SIZE),
            p1=pt_pair.m1  # <--- ZAPISUJEMY TEKST JAWNY
        )
        
        ct_collection.add(ct_pair)

    ct_collection.save()
    return ct_collection.id # Zwracamy ID, żeby orchestrator wiedział co wczytać

if __name__ == "__main__":
    run_generation()
