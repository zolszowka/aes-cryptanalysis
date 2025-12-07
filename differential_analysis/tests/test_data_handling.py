import shutil

from differential_analysis.data_models.collections.diff_pair_collection import DiffPairCollection
from differential_analysis.data_models.diff_pair import DiffPair
from differential_analysis.data_models.block import Block

# Sprzątanie poprzednich testów (opcjonalne)
try:
    shutil.rmtree("data")
except: pass

print("--- 1. TWORZENIE DANYCH ---")
# Tworzymy bloki
b1 = Block(0xA1B2, size_bits=16)
b2 = Block(0xA1B2 ^ 0x000B, size_bits=16) # Delta B

# Tworzymy parę
para = DiffPair(b1, b2)
print(f"Oryginał: {para}, Typ m1: {type(para.m1)}")

# Dodajemy do kolekcji i zapisujemy
col = DiffPairCollection(name="test_ataku")
col.add(para)
col.save() # Zapisuje kolekcję (listę ID)

col_id = col.id
print(f"Zapisano kolekcję ID: {col_id}")

print("\n--- 2. ODCZYT DANYCH (Nowa sesja) ---")
# Symulujemy restart programu - ładujemy od zera
loaded_col = DiffPairCollection.load(col_id)

# Pobieramy pierwszą parę
loaded_pair = loaded_col.get_pair(0)

print(f"Wczytano: {loaded_pair}")
print(f"Typ m1: {type(loaded_pair.m1)}") # Sprawdźmy czy to Block czy dict
print(f"Wartość m1: {loaded_pair.m1.value:X}")

# Sprawdzenie tożsamości
assert isinstance(loaded_pair.m1, Block)
assert loaded_pair.m1.value == 0xA1B2
print("\nSUKCES: Dane wczytane poprawnie jako obiekty Block!")
