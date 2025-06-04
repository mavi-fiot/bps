from ecpy.curves import Curve, Point, ECPyException

# Вибір кривої
curve = Curve.get_curve("Ed25519")

# Тестові координати (встав свої)
x = 27792152936360649687448976353883632062344703197977593442879046769164623510768
y = 30899990285690074025798565551082202732112225468277011525467046934534475024524

try:
    point = Point(x, y, curve)
    if curve.is_on_curve(point):
        print("✅ Точка валідна і належить кривій Ed25519")
    else:
        print("❌ Точка не належить кривій")
except ECPyException:
    print("❌ Помилка: координати не утворюють точку на кривій Ed25519")
