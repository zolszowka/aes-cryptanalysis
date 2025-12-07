from differential_analysis.data_models.data_model import DataModel

class Block(DataModel):
    BASE_DIR = f"{DataModel.BASE_DIR}/blocks"

    def __init__(self, value: int, size_bits: int = 16, uid=None):
        super().__init__(uid)
        self.size = size_bits
        self.mask = (1 << size_bits) - 1
        self.value = value & self.mask
        self.hex_width = (size_bits + 3) // 4

    # --- Implementacja metod abstrakcyjnych DataModel ---

    def to_dict(self) -> dict:
        """Zapisuje stan Bloku."""
        return {
            "val": self.value,
            "bits": self.size
        }

    @classmethod
    def from_dict(cls, data: dict):
        """Odtwarza obiekt Block."""
        uid = data.get('id', None)
        return cls(value=data["val"], size_bits=data["bits"], uid=uid)

    def get_nibble(self, index: int) -> int:
        total_nibbles = (self.size + 3) // 4
        if index < 0 or index >= total_nibbles:
            raise IndexError("Indeks nibbla poza zakresem")
        shift = (total_nibbles - 1 - index) * 4
        return (self.value >> shift) & 0xF

    def __xor__(self, other):
        if isinstance(other, Block):
            if self.size != other.size:
                raise ValueError("Różne rozmiary bloków przy XOR")
            return Block(self.value ^ other.value, self.size)
        return Block(self.value ^ other, self.size)

    def __eq__(self, other):
        if isinstance(other, Block):
            return self.value == other.value and self.size == other.size
        return False

    def __repr__(self):
        return f"Block(0x{self.value:0{self.hex_width}X})"

    def replace_nibble(self, index: int, val: int) -> 'Block':
        """Tworzy nowy Blok z podmienionym nibblem."""
        total_nibbles = (self.size + 3) // 4
        shift = (total_nibbles - 1 - index) * 4
        
        nibble_mask = ~(0xF << shift) & self.mask

        new_value = (self.value & nibble_mask) | ((val & 0xF) << shift)
        return Block(new_value, self.size)

    def __int__(self):
        return self.value

    def details(self):
        return f"Block(val=0x{self.value:X}, bits={self.size}, bin={self.value:0{self.size}b})"
