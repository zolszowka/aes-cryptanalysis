from differential_analysis.data_models.data_model import DataModel
from differential_analysis.data_models.diff_pair import DiffPair

class DiffPairCollection(DataModel):
    BASE_DIR = f"{DataModel.BASE_DIR}/collections"

    def __init__(self, name="default_collection", uid=None):
        super().__init__(uid)
        self.name = name
        self.pair_ids = []
        self._cache = {}

    def add(self, pair: DiffPair):
        """Dodaje parę do kolekcji i zapisuje ją fizycznie na dysku."""
        pair.save()
        
        if pair.id not in self.pair_ids:
            self.pair_ids.append(pair.id)
            self._cache[pair.id] = pair

    def get_pair(self, index: int) -> DiffPair:
        """Pobiera obiekt pary (z cache lub z dysku)."""
        pid = self.pair_ids[index]
        
        if pid in self._cache:
            return self._cache[pid]
        
        pair = DiffPair.load(pid)
        self._cache[pid] = pair
        return pair

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "pair_ids": self.pair_ids
        }

    @classmethod
    def from_dict(cls, data: dict):
        col = cls(name=data["name"])
        col.pair_ids = data["pair_ids"]
        return col

    def __len__(self):
        return len(self.pair_ids)

    def __iter__(self):
        for i in range(len(self)):
            yield self.get_pair(i)