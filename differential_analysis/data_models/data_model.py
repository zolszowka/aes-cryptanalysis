import json
import os
import uuid
from abc import ABC, abstractmethod

from differential_analysis.settings import DATA_DIR

class DataModel(ABC):
    """
    Abstrakcyjna klasa bazowa obsługująca zapis i odczyt JSON z unikalnym ID (UUID).
    """

    BASE_DIR = DATA_DIR

    def __init__(self, uid=None):
        self.id = uid if uid else str(uuid.uuid4())

    @abstractmethod
    def to_dict(self) -> dict:
        """Zwraca słownik reprezentujący stan obiektu."""
        pass

    @classmethod
    @abstractmethod
    def from_dict(cls, data: dict):
        """Rekonstruuje obiekt ze słownika."""
        pass

    def get_filepath(self):
        """Zwraca pełną ścieżkę do pliku JSON dla tego obiektu."""
        filename = f"{self.id}.json"
        return os.path.join(self.BASE_DIR, filename)

    def save(self):
        """Zapisuje obiekt do pliku JSON."""
        os.makedirs(self.BASE_DIR, exist_ok=True)
        path = self.get_filepath()
        
        data = self.to_dict()
        data['id'] = self.id
        
        with open(path, 'w') as f:
            json.dump(data, f, indent=4)

    @classmethod
    def load(cls, uid: str):
        """Wczytuje obiekt z dysku na podstawie ID."""
        filepath = os.path.join(cls.BASE_DIR, f"{uid}.json")
        
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Brak pliku: {filepath}")

        with open(filepath, 'r') as f:
            data = json.load(f)

        obj = cls.from_dict(data)
        obj.id = data.get('id', uid)
        return obj