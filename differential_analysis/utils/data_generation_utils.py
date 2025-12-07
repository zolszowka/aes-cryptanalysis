import random

from differential_analysis.data_models.block import Block
from differential_analysis.data_models.diff_pair import DiffPair

def generate_random_pair(delta_val: int, size_bits: int = 16) -> DiffPair:
    delta_block = Block(delta_val, size_bits)
    max_val = (1 << size_bits) - 1
    
    val1 = random.randint(0, max_val)
    b1 = Block(val1, size_bits)
    b2 = b1 ^ delta_block
    
    return DiffPair(b1, b2)

# TODO: sprawdzić czy ostatecznie gdzieś tego używałem/mogę użyć
def populate_collection(collection, count: int, delta_val: int):
    print(f"Generuję {count} par...")
    for _ in range(count):
        pair = generate_random_pair(delta_val)
        collection.add(pair)