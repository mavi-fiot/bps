# vote_process.py
from ecpy.curves import Curve, Point
from crypto.hash_util import hash_ballot
from crypto.encryption import encrypt_hash, decrypt_ciphertext, verify_decrypted_point
from crypto.signature import sign_hash, verify_signature
from kzp.store import BallotStorage
from kzp.signer import BallotSigner
from kzp.keys import server_priv, server_pub, secretary_priv, secretary_pub, kep_priv, kep_pub, voter_pub

curve = Curve.get_curve('Ed25519')
G = curve.generator

signer = BallotSigner(server_priv, secretary_priv, kep_priv, G)
storage = BallotStorage()

def submit_vote(voter_id: str, ballot_text: str) -> None:
    # 1️⃣ Хеш бюлетеня
    hash_scalar = hash_ballot(ballot_text)

    # 2️⃣ Підписання
    signatures = signer.sign_all(ballot_text)

    # 3️⃣ Шифрування
    C1, C2 = encrypt_hash(hash_scalar, voter_pub)

    # 4️⃣ Збереження
    storage.store_encrypted(voter_id, {
        'C1': C1,
        'C2': C2,
        'signatures': signatures
    })

    print(f"✅ Голос для {voter_id} збережено.")

def verify_vote(voter_id: str, ballot_text: str) -> bool:
    entry = storage.retrieve_for_decryption(voter_id)
    if not entry:
        print("❌ Голос не знайдено")
        return False

    hash_scalar = hash_ballot(ballot_text)
    C1, C2 = entry['C1'], entry['C2']
    signatures = entry['signatures']

    # 1️⃣ Розшифрування
    decrypted = decrypt_ciphertext(C1, C2, server_priv)

    # 2️⃣ Перевірка
    match = verify_decrypted_point(decrypted, hash_scalar)
    print(f"📥 Хеш співпадає: {'✅' if match else '❌'}")

    # 3️⃣ Перевірка підписів
    server_valid = verify_signature(hash_scalar, signatures['server_signature'], server_pub)
    secretary_valid = verify_signature(hash_scalar, signatures['secretary_signature'], secretary_pub)
    kep_valid = verify_signature(hash_scalar, signatures['kep_signature'], kep_pub)

    print("🔐 Підписи:")
    print(f" - Сервер: {'✅' if server_valid else '❌'}")
    print(f" - Секретар: {'✅' if secretary_valid else '❌'}")
    print(f" - КЕП: {'✅' if kep_valid else '❌'}")

    return match and server_valid and secretary_valid and kep_valid

if __name__ == "__main__":
    voter_id = "user123"
    ballot = "Голосую 'За' питання №1"
    submit_vote(voter_id, ballot)
    verify_vote(voter_id, ballot)

