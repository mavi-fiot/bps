#models/crypto_schemas.py

from pydantic import BaseModel

# 📍 Точка на кривій
class PointData(BaseModel):
    x: int
    y: int

# 🔐 Вхідне повідомлення для підпису і шифрування голосу
class VoteIn(BaseModel):
    voter_id: str
    ballot_id: str
    choice: str
    signature: PointData
    public_key: PointData

# 📦 Структура для збереження результатів подвійного шифрування
class EncryptedData(BaseModel):
    C1_srv: tuple[int, int]
    C2_srv: tuple[int, int]
    C1_sec: tuple[int, int]
    C2_sec: tuple[int, int]
    expected_hash_scalar: int

# 📤 Демонстраційна відповідь із `/encrypt_demo`
class EncryptDemoResponse(BaseModel):
    message: str
    hash_scalar: int
    point_M: PointData
    server_public_key: PointData
    secretary_public_key: PointData
    C1_srv: PointData
    C2_srv: PointData
    C1_sec: PointData
    C2_sec: PointData

# 📥 Результат розшифрування з /decrypt_demo
class DecryptDemoResponse(BaseModel):
    decrypted_point: PointData
    expected_point: PointData
    valid: bool