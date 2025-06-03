# === kzp/signer.py ===
from ecpy.curves import Point
from crypto.hash_util import hash_ballot
from crypto.signature import sign_hash
from kzp.keys import SERVER_PRIV, SECRETARY_PRIV, KEP_PRIV, G

# Модель підпису бюлетеня: сервер, секретар, КЕП
class BallotSigner:
    def sign_by_server(self, hash_scalar: int) -> Point:
        return sign_hash(hash_scalar, SERVER_PRIV)

    def sign_by_secretary(self, hash_scalar: int) -> Point:
        return sign_hash(hash_scalar, SECRETARY_PRIV)

    def sign_by_kep(self, hash_scalar: int) -> Point:
        return sign_hash(hash_scalar, KEP_PRIV)

    def sign_all(self, ballot_text: str) -> dict:
        hash_scalar = hash_ballot(ballot_text)
        return {
            'hash': hash_scalar,
            'server_signature': self.sign_by_server(hash_scalar),
            'secretary_signature': self.sign_by_secretary(hash_scalar),
            'kep_signature': self.sign_by_kep(hash_scalar)
        }
