from differential_analysis.data_models.block import Block
from differential_analysis.data_models.data_model import DataModel

class DiffPair(DataModel):
    BASE_DIR = f"{DataModel.BASE_DIR}/pairs"

    def __init__(self, m1: Block, m2: Block, p1: Block = None, uid=None):
        super().__init__(uid)
        self.m1 = m1
        self.m2 = m2
        self.p1 = p1

    def save(self):
        self.m1.save()
        self.m2.save()
        # Zapisz też blok P1 jeśli istnieje
        if self.p1:
            self.p1.save()
        super().save()

    def to_dict(self) -> dict:
        data = {
            "m1_id": self.m1.id,
            "m2_id": self.m2.id
        }
        # Zapisujemy ID bloku P1 tylko jeśli istnieje
        if self.p1:
            data["p1_id"] = self.p1.id
        return data

    @classmethod
    def from_dict(cls, data):
        b1 = Block.load(data["m1_id"])
        b2 = Block.load(data["m2_id"])
        
        # Wczytujemy P1 jeśli jest w pliku
        p1 = None
        if "p1_id" in data:
            p1 = Block.load(data["p1_id"])

        return cls(m1=b1, m2=b2, p1=p1)

    @property
    def delta(self) -> Block:
        return self.m1 ^ self.m2

    def __repr__(self):
        return f"DiffPair[{self.id[:4]}..] ({self.m1} ^ {self.m2})"
