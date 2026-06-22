"""
Recalibracion de pesos con datos historicos organizacionales
Caso 3 - Correccion del feedback del profesor (punto 1)

El profesor observo que calibrar (alpha, beta, gamma) una sola vez con un
dataset externo (FIRST/EPSS, 214,000 CVEs) no necesariamente refleja el
comportamiento real de una institucion especifica. Este script implementa
el mecanismo de DOS FASES propuesto como correccion:

  Fase 0 (cold start): (alpha_0, beta_0, gamma_0) = (0.40, 0.35, 0.25),
  calibrados con el dataset publico NVD/EPSS (ya validado en el TC1 con
  el analisis de sensibilidad de Sobol).

  Fase 1 (recalibracion continua): cuando la organizacion acumula un
  historial propio de N decisiones (¿el riesgo estimado se materializo
  en un incidente real o no?), se reestima (alpha_org, beta_org,
  gamma_org) con regresion logistica sobre esos datos, y se combina con
  el prior de Fase 0 mediante un estimador de shrinkage:

      alpha_t = (1 - lambda) * alpha_0 + lambda * alpha_org

  donde lambda crece con el tamano de muestra disponible (mientras mas
  datos propios existan, mas se confia en ellos y menos en el prior
  generico).
"""
import json
import os

try:
    from sklearn.linear_model import LogisticRegression
    import numpy as np
    SKLEARN_DISPONIBLE = True
except ImportError:
    SKLEARN_DISPONIBLE = False

PESOS_COLD_START = {"alpha": 0.40, "beta": 0.35, "gamma": 0.25}


def calcular_lambda(n_muestras, n_min=10, n_saturacion=200):
    """
    Factor de mezcla entre el prior (dataset externo) y los datos propios
    de la organizacion. Por debajo de n_min muestras, lambda=0 (no hay
    suficiente evidencia propia, se usa solo el cold-start). A partir de
    n_saturacion muestras, lambda=0.8 (se confia mayormente en los datos
    organizacionales, sin descartar nunca del todo el prior).
    """
    if n_muestras < n_min:
        return 0.0
    proporcion = (n_muestras - n_min) / (n_saturacion - n_min)
    return min(0.8, max(0.0, proporcion * 0.8))


def reestimar_pesos_organizacionales(registros):
    """
    Ajusta una regresion logistica sobre los registros historicos
    (V, E, C) -> incidente_materializado, y normaliza los coeficientes
    resultantes para que sumen 1 y sean no negativos (restriccion de
    convexidad del modelo original, Seccion 2.2 del TC1).
    """
    if not SKLEARN_DISPONIBLE:
        raise RuntimeError("scikit-learn no esta instalado. Ejecutar: pip install scikit-learn")

    X = np.array([[r["V"], r["E"], r["C"]] for r in registros])
    y = np.array([r["incidente_materializado"] for r in registros])

    modelo = LogisticRegression()
    modelo.fit(X, y)

    coef = modelo.coef_[0]
    coef_no_negativos = np.clip(coef, 0, None)  # restriccion de convexidad
    if coef_no_negativos.sum() == 0:
        coef_normalizados = np.array([1 / 3, 1 / 3, 1 / 3])
    else:
        coef_normalizados = coef_no_negativos / coef_no_negativos.sum()

    return {
        "alpha": round(float(coef_normalizados[0]), 4),
        "beta": round(float(coef_normalizados[1]), 4),
        "gamma": round(float(coef_normalizados[2]), 4),
    }


def recalibrar(registros):
    """Combina el prior cold-start con los pesos reestimados via shrinkage."""
    n = len(registros)
    lam = calcular_lambda(n)
    pesos_org = reestimar_pesos_organizacionales(registros) if n >= 10 else PESOS_COLD_START

    pesos_combinados = {
        k: round((1 - lam) * PESOS_COLD_START[k] + lam * pesos_org[k], 4)
        for k in ("alpha", "beta", "gamma")
    }
    # Renormalizar para garantizar suma exacta = 1 tras el redondeo
    total = sum(pesos_combinados.values())
    pesos_combinados = {k: round(v / total, 4) for k, v in pesos_combinados.items()}

    return {
        "n_muestras_organizacionales": n,
        "lambda_mezcla": round(lam, 3),
        "pesos_cold_start": PESOS_COLD_START,
        "pesos_reestimados_organizacion": pesos_org,
        "pesos_combinados_finales": pesos_combinados,
    }


def main():
    data_path = os.path.join(os.path.dirname(__file__), "..", "data", "historical_incidents_sample.json")
    with open(data_path) as f:
        data = json.load(f)

    resultado = recalibrar(data["registros"])
    print(json.dumps(resultado, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
