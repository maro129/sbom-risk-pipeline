"""
Motor de Logica Difusa Mamdani - Caso 3 (DevSecOps y Scoring de Riesgo en SBOM)

Implementacion directa de la Seccion 2.4 del TC1: cinco conjuntos difusos
trapezoidales sobre el universo [0, 10], con solapamiento entre conjuntos
adyacentes y defuzzificacion por centroide (Center of Gravity).

Esta parte del modelo NO requirio correccion segun el feedback del profesor;
se reutiliza tal cual fue disenada y validada en el TC1.
"""

CONJUNTOS = {
    "MUY_BAJO":   (0.0, 0.0, 1.5, 2.5),
    "BAJO_MEDIO": (1.5, 2.5, 4.0, 5.0),
    "MEDIO_ALTO": (4.0, 5.0, 6.5, 7.5),
    "ALTO":       (6.5, 7.5, 9.0, 10.0),
    "MUY_ALTO":   (9.0, 10.0, 10.0, 10.0),
}

ACCION_POR_CONJUNTO = {
    "MUY_BAJO":   {"accion": "monitor_30d", "policy": "PASS"},
    "BAJO_MEDIO": {"accion": "patch_next_sprint", "policy": "PASS"},
    "MEDIO_ALTO": {"accion": "patch_7d_alert", "policy": "PASS_CON_ALERTA"},
    "ALTO":       {"accion": "block_deploy_patch_48h", "policy": "BLOCK"},
    "MUY_ALTO":   {"accion": "rollback_p0_incident", "policy": "BLOCK"},
}


def membresia_trapezoidal(x, a, b, c, d):
    """mu(x; a,b,c,d) - funcion de membresia trapezoidal general (Seccion 2.4 TC1)."""
    if x <= a or x > d:
        return 0.0
    if a < x <= b:
        return (x - a) / (b - a) if b != a else 1.0
    if b < x <= c:
        return 1.0
    if c < x <= d:
        return (d - x) / (d - c) if d != c else 1.0
    return 0.0


def grados_membresia(r_score):
    """Devuelve el grado de activacion de cada conjunto difuso para un R_score dado."""
    return {
        nombre: membresia_trapezoidal(r_score, *params)
        for nombre, params in CONJUNTOS.items()
    }


def clasificar(r_score, tau=1.0):
    """
    Clasifica un R_score aplicando el motor Mamdani y devuelve la decision
    del Policy Gate. `tau` es el multiplicador de apetito de riesgo
    organizacional (ver asset-inventory/inventory.json): se aplica
    escalando el r_score efectivo antes de evaluar los conjuntos, de modo
    que organizaciones con menor apetito de riesgo (tau<1, ej. banca)
    activan el bloqueo con scores mas bajos que una con mayor apetito
    (tau>1, ej. startup).
    """
    r_efectivo = min(10.0, r_score / tau) if tau > 0 else r_score
    grados = grados_membresia(r_efectivo)

    # Conjunto(s) con mayor grado de activacion (puede haber solapamiento)
    activos = {k: v for k, v in grados.items() if v > 0}
    if not activos:
        conjunto_dominante = "MUY_BAJO"
    else:
        conjunto_dominante = max(activos, key=activos.get)

    decision = ACCION_POR_CONJUNTO[conjunto_dominante]

    return {
        "r_score": round(r_score, 2),
        "r_efectivo_tau": round(r_efectivo, 2),
        "grados_membresia": {k: round(v, 3) for k, v in grados.items()},
        "conjunto_dominante": conjunto_dominante,
        "accion": decision["accion"],
        "policy_gate": decision["policy"],
    }


if __name__ == "__main__":
    # Ejemplo de verificacion: R_score = 7.3 (igual al ejemplo del TC1)
    resultado = clasificar(7.3)
    print(resultado)
