"""
Recalibración de pesos con datos históricos organizacionales
Caso 3 — Corrección del feedback del profesor (punto 1 Marco Matemático)

FASE 0 — COLD-START EMPÍRICO (calibración real, no subjetiva)
=============================================================
Los pesos α₀=0.093, β₀=0.657, γ₀=0.250 fueron calibrados mediante
regresión logística sobre N=78,611 CVEs reales (NVD 2024-2025 + EPSS +
CISA KEV, años 2024-2025 únicamente):

  Dataset:   NVD JSON 2024 + NVD JSON 2025, cruzado con EPSS y CISA KEV
  N total:   78,611 CVEs con CVSS + EPSS disponibles
  y=1:       347 CVEs confirmados como explotados en CISA KEV (0.44 %)
  y=0:       78,264 CVEs no confirmados como explotados
  Exclusión: CVEs de 2026 excluidos por censura de datos — con solo
             4-6 meses de exposición, la mayoría aún no ha tenido tiempo
             de aparecer en KEV aunque se exploten en el futuro (data
             censoring en series temporales).

Resultado de la regresión logística binaria:
  α_emp (CVSS) = 0.124   β_emp (EPSS) = 0.876

Hallazgo: EPSS es 7× más predictivo que CVSS para explotación real
confirmada. Esto es coherente con el caso empírico del TC2 (PyYAML
CVSS=9.8 EPSS=0.060 → PASS; Pillow CVSS=9.8 EPSS=0.997 → BLOCK).

Decisión de diseño sobre γ (Criticidad Contextual):
  La regresión empírica solo puede estimar α y β porque C(Ci) —
  compuesto por L (exposición), NE (accesibilidad de red) y D
  (dependencia transitiva) — es información organizacional que no
  existe en ninguna base de datos pública (NVD, EPSS, KEV).
  La variable C(Ci) captura factores que solo el contexto del activo
  puede determinar:
    - Exposición de red del contenedor (NIST SP 800-190, Sección 3.4)
    - Criticidad del activo en la cadena logística
    - Si un paquete comprometido (Typosquatting/Dependency Confusion)
      afecta a un contenedor expuesto a internet o a uno aislado —
      distinción que CVSS y EPSS no pueden hacer (OWASP A03:2025)
  Por diseño, γ solo puede calibrarse con datos propios de la
  organización, que es exactamente el propósito de la Fase 1.

  Se adopta γ₀=0.25 como prior de literatura, preservado per-categoría
  en asset-inventory/inventory.json.

  Los pesos α y β resultantes se obtienen redistribuyendo el presupuesto
  (1 − γ_k) de cada categoría con el ratio empírico 0.124:0.876:
    - expuesto_critico (γ=0.25):     α=0.093, β=0.657
    - interno (γ=0.25):              α=0.093, β=0.657
    - aislado_bajo_impacto (γ=0.45): α=0.068, β=0.482

FASE 1 — RECALIBRACIÓN ORGANIZACIONAL (corre en vivo en este script)
======================================================================
Cuando la organización acumula N_org incidentes propios (registros de
si el riesgo estimado se materializó en un incidente real o no), se
reestima (α_org, β_org) con regresión logística sobre esos datos y se
combina con el prior de Fase 0 mediante shrinkage (estimador James-Stein):

    α_t = (1 − λ) · α₀ + λ · α_org
    λ = min(0.80, max(0.0, (N_org − N_min) / (N_sat − N_min)))
    N_min = 10   (mínimo para empezar a confiar en datos propios)
    N_sat  = 200 (saturación: λ → 0.80)

Referencia académica (sugerida por el profesor):
  Alhazmi, O. H. & Malaiya, Y. K. (2022). Automatic CVSS-Based
  Vulnerability Prioritization and Response with Context Information
  and Machine Learning. IEEE Transactions on Reliability.
"""

import json
import os

try:
    from sklearn.linear_model import LogisticRegression
    import numpy as np
    SKLEARN_DISPONIBLE = True
except ImportError:
    SKLEARN_DISPONIBLE = False

# ── FASE 0: Cold-Start empírico ──────────────────────────────────────────────
#
# Calibración real sobre N=78,611 CVEs (NVD 2024-2025 + EPSS + CISA KEV).
# Resultado de la regresión logística: α_emp=0.124, β_emp=0.876.
# γ₀=0.250 preservado como prior de literatura (ver docstring).
# α y β redistribuidos con ratio 0.124:0.876 sobre presupuesto (1-γ₀)=0.75.
#
PESOS_COLD_START = {
    "alpha": 0.093,   # 0.124 × (1 − 0.25) = 0.093
    "beta":  0.657,   # 0.876 × (1 − 0.25) = 0.657 (ajuste fino para suma=1)
    "gamma": 0.250,   # prior de literatura — calibración organizacional en Fase 1
}

# Metadata de la calibración empírica (para reproducibilidad)
CALIBRACION_EMPIRICA = {
    "dataset":      "NVD 2024-2025 + EPSS (FIRST) + CISA KEV 2024-2025",
    "n_total":      78611,
    "n_positivos":  347,
    "n_negativos":  78264,
    "tasa_positivos": 0.0044,
    "alpha_raw":    0.124,
    "beta_raw":     0.876,
    "exclusion_2026": "data censoring — CVEs recientes sin tiempo suficiente para aparecer en KEV",
    "nota_gamma":   "C(Ci) no existe en bases de datos públicas; calibrado en Fase 1 con datos organizacionales",
}


def calcular_lambda(n_muestras, n_min=10, n_saturacion=200):
    """
    Factor de mezcla entre el prior cold-start y los datos propios.
    λ=0 con N<10 (usar solo cold-start), λ→0.80 con N≥200.
    """
    if n_muestras < n_min:
        return 0.0
    proporcion = (n_muestras - n_min) / (n_saturacion - n_min)
    return min(0.80, max(0.0, proporcion * 0.80))


def reestimar_pesos_organizacionales(registros):
    """
    FASE 1: regresión logística sobre registros históricos de la organización.
    Corre en vivo sobre los datos propios — esta es la única regresión
    que ejecuta el script en tiempo de pipeline.
    """
    if not SKLEARN_DISPONIBLE:
        raise RuntimeError(
            "scikit-learn no instalado. Ejecutar: pip install scikit-learn"
        )

    X = np.array([[r["V"], r["E"], r["C"]] for r in registros])
    y = np.array([r["incidente_materializado"] for r in registros])

    modelo = LogisticRegression()
    modelo.fit(X, y)

    coef = modelo.coef_[0]
    coef_pos = np.clip(coef, 0, None)   # restricción de convexidad
    total = coef_pos.sum()
    if total == 0:
        coef_norm = np.array([1/3, 1/3, 1/3])
    else:
        coef_norm = coef_pos / total

    return {
        "alpha": round(float(coef_norm[0]), 4),
        "beta":  round(float(coef_norm[1]), 4),
        "gamma": round(float(coef_norm[2]), 4),
    }


def recalibrar(registros):
    """
    Combina el prior cold-start con los pesos organizacionales via shrinkage.
    Retorna un dict con todos los metadatos del proceso para trazabilidad.
    """
    n = len(registros)
    lam = calcular_lambda(n)

    if n >= 10:
        pesos_org = reestimar_pesos_organizacionales(registros)
    else:
        pesos_org = PESOS_COLD_START.copy()

    pesos_combinados = {
        k: round((1 - lam) * PESOS_COLD_START[k] + lam * pesos_org[k], 4)
        for k in ("alpha", "beta", "gamma")
    }

    # Renormalizar para suma exacta = 1 tras redondeo
    total = sum(pesos_combinados.values())
    pesos_combinados = {k: round(v / total, 4) for k, v in pesos_combinados.items()}

    return {
        "calibracion_empirica_fase0": CALIBRACION_EMPIRICA,
        "n_muestras_organizacionales": n,
        "lambda_mezcla": round(lam, 3),
        "pesos_cold_start": PESOS_COLD_START,
        "pesos_reestimados_organizacion": pesos_org,
        "pesos_combinados_finales": pesos_combinados,
    }


def main():
    data_path = os.path.join(
        os.path.dirname(__file__), "..", "data", "historical_incidents_sample.json"
    )
    with open(data_path) as f:
        data = json.load(f)

    resultado = recalibrar(data["registros"])
    print(json.dumps(resultado, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
