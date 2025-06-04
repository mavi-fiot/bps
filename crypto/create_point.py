from ecpy.curves import Curve

curve = Curve.get_curve("Ed25519")
G = curve.generator
q = curve.order

# Випадкове скалярне число (1 ≤ k < q)
import secrets
k = secrets.randbelow(q)
P = k * G  # Точка на кривій

print(f"✅ Валідна точка: ({P.x}, {P.y})")
