# === kzp/keys.py ===
from ecpy.curves import Curve

# Вибір кривої
curve = Curve.get_curve('Ed25519')
G = curve.generator
q = curve.order

# Постійні ключі для підписантів (у реальній системі — безпечне зберігання!)
import secrets
SERVER_PRIV = secrets.randbelow(q)
SECRETARY_PRIV = secrets.randbelow(q)
KEP_PRIV = secrets.randbelow(q)