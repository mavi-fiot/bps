# === kzp/store.py ===

from typing import Dict, Any
from ecpy.curves import Point


class BallotStorage:
    """
    Клас для зберігання зашифрованих та підписаних бюлетенів до моменту розшифрування.

    Структура запису:
    {
        "hash": int,
        "C1": Point,
        "C2": Point,
        "server_signature": Point,
        "secretary_signature": Point,
        "kep_signature": Point
    }
    """

    def __init__(self):
        self._store: Dict[str, Dict[str, Any]] = {}

    def store_encrypted(self, voter_id: str, encrypted_data: Dict[str, Any]) -> None:
        """
        Зберігає зашифрований бюлетень та підписи для вказаного виборця.

        :param voter_id: унікальний ідентифікатор виборця
        :param encrypted_data: словник з полями hash, C1, C2, signatures
        """
        self._store[voter_id] = encrypted_data

    def retrieve_for_decryption(self, voter_id: str) -> Dict[str, Any]:
        """
        Повертає збережений запис для розшифрування.
        :param voter_id: ідентифікатор виборця
        :return: словник з hash, C1, C2, signatures
        """
        return self._store.get(voter_id, {})

    def get_all_ballots(self) -> Dict[str, Dict[str, Any]]:
        """
        Повертає всі збережені бюлетені.
        :return: словник {voter_id: encrypted_data}
        """
        return self._store

    def clear_storage(self) -> None:
        """
        Очищає всі збережені бюлетені (наприклад, після підрахунку або завершення голосування).
        """
        self._store.clear()
