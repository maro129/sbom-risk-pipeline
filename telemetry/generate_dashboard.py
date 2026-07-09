"""
Validacion Analitica y Telemetria - Caso 3 (versión con pesos calibrados)

Genera el grafico comparativo entre:
  - Modelo ANTES de la correccion (alpha=0.40, beta=0.35, gamma=0.25 — subjetivos)
  - Modelo DESPUES de la correccion (alpha_emp=0.124, beta_emp=0.876 — calibrados
    sobre N=78,611 CVEs reales NVD 2024-2025 + EPSS + CISA KEV)

Los vectores por categoria se obtienen redistribuyendo el presupuesto (1-gamma_k)
con el ratio empirico 0.124:0.876, preservando gamma_k como prior de literatura
(NIST SP 800-190, OWASP A03:2025, Jiang et al. 2025).
"""
import json
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

# ── Pesos ANTES (subjetivos — TC1 original) ───────────────────────────────────
VECTORES_ANTES = {
    "expuesto_critico":     {"alpha": 0.35, "beta": 0.40, "gamma": 0.25},
    "interno":              {"alpha": 0.40, "beta": 0.35, "gamma": 0.25},
    "aislado_bajo_impacto": {"alpha": 0.30, "beta": 0.25, "gamma": 0.45},
}

# ── Pesos DESPUES (calibrados empiricamente — N=78,611 CVEs) ──────────────────
VECTORES_DESPUES = {
    "expuesto_critico":     {"alpha": 0.093, "beta": 0.657, "gamma": 0.250},
    "interno":              {"alpha": 0.093, "beta": 0.657, "gamma": 0.250},
    "aislado_bajo_impacto": {"alpha": 0.068, "beta": 0.482, "gamma": 0.450},
}

# ── Activos del TC2 (datos reales del pipeline) ───────────────────────────────
ACTIVOS = [
    {"nombre": "API Tracking\nPúblico\n(PyYAML 5.3.1)",    "cat": "expuesto_critico",    "V": 0.980, "E": 0.060, "C": 0.867},
    {"nombre": "Serv. Inventario\nInterno\n(Pillow 8.1.0)", "cat": "interno",             "V": 0.750, "E": 0.997, "C": 0.467},
    {"nombre": "Utilidad de\nLogging\n(Werkzeug 0.15.0)",  "cat": "aislado_bajo_impacto", "V": 0.750, "E": 0.555, "C": 0.150},
]

UMBRAL_BLOCK = 7.5


def calcular_r_score(activo, vectores):
    p = vectores[activo["cat"]]
    R = p["alpha"] * activo["V"] + p["beta"] * activo["E"] + p["gamma"] * activo["C"]
    return round(R * 10, 2)


def policy_color(rs):
    if rs >= UMBRAL_BLOCK:
        return "#d62728"
    if rs >= 5.0:
        return "#ff7f0e"
    return "#2ca02c"


def policy_label(rs):
    if rs >= UMBRAL_BLOCK:
        return "BLOCK"
    if rs >= 5.0:
        return "PASS ALERTA"
    return "PASS"


def generar_dashboard(salida_png):
    import numpy as np

    nombres = [a["nombre"] for a in ACTIVOS]
    r_antes   = [calcular_r_score(a, VECTORES_ANTES)   for a in ACTIVOS]
    r_despues = [calcular_r_score(a, VECTORES_DESPUES) for a in ACTIVOS]

    x = np.arange(len(ACTIVOS))
    w = 0.35

    fig, axes = plt.subplots(1, 2, figsize=(14, 6))
    fig.suptitle(
        "Validación Analítica y Telemetría — Caso 3: DevSecOps SBOM\n"
        "CBS07 UNI 2026-I — Comparativa de modelos de scoring",
        fontsize=12, fontweight="bold"
    )

    # ── Gráfico 1: R_score antes vs después ──────────────────────────────────
    ax1 = axes[0]
    bars1 = ax1.bar(x - w/2, r_antes,   w, color=[policy_color(r) for r in r_antes],
                    alpha=0.88, label="Antes (subjetivos α=0.40, β=0.35, γ=0.25)")
    bars2 = ax1.bar(x + w/2, r_despues, w, color=[policy_color(r) for r in r_despues],
                    alpha=0.55, label="Después (calibrados N=78,611 CVEs)", hatch="///")

    ax1.axhline(y=UMBRAL_BLOCK, color="black", linestyle="--", linewidth=1.5,
                label=f"Umbral de bloqueo ({UMBRAL_BLOCK})")
    ax1.axhspan(UMBRAL_BLOCK, 11, alpha=0.05, color="red")

    for bar, rs in zip(bars1, r_antes):
        ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.2,
                 f"{rs}\n{policy_label(rs)}", ha="center", fontsize=8, fontweight="bold")
    for bar, rs in zip(bars2, r_despues):
        ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.2,
                 f"{rs}\n{policy_label(rs)}", ha="center", fontsize=8)

    ax1.set_xticks(x)
    ax1.set_xticklabels(nombres, fontsize=9)
    ax1.set_ylim(0, 12)
    ax1.set_ylabel("R_score (0–10)")
    ax1.set_title("R_score: modelo subjetivo vs calibrado empíricamente")
    ax1.legend(fontsize=8)
    ax1.grid(axis="y", alpha=0.3, linestyle=":")
    ax1.spines["top"].set_visible(False)
    ax1.spines["right"].set_visible(False)

    # ── Gráfico 2: Desglose vectores de pesos ────────────────────────────────
    ax2 = axes[1]
    cats = list(VECTORES_ANTES.keys())
    labels_cats = ["expuesto\ncritico", "interno", "aislado\nbajo impacto"]

    alpha_antes   = [VECTORES_ANTES[c]["alpha"]   for c in cats]
    beta_antes    = [VECTORES_ANTES[c]["beta"]    for c in cats]
    gamma_antes   = [VECTORES_ANTES[c]["gamma"]   for c in cats]
    alpha_despues = [VECTORES_DESPUES[c]["alpha"] for c in cats]
    beta_despues  = [VECTORES_DESPUES[c]["beta"]  for c in cats]
    gamma_despues = [VECTORES_DESPUES[c]["gamma"] for c in cats]

    xc = np.arange(len(cats))
    w2 = 0.15

    ax2.bar(xc - w2*2, alpha_antes,   w2, color="#4878cf", alpha=0.88, label="α antes")
    ax2.bar(xc - w2,   beta_antes,    w2, color="#d62728", alpha=0.88, label="β antes")
    ax2.bar(xc,        gamma_antes,   w2, color="#6acc65", alpha=0.88, label="γ antes")
    ax2.bar(xc + w2,   alpha_despues, w2, color="#4878cf", alpha=0.45, label="α después", hatch="///")
    ax2.bar(xc + w2*2, beta_despues,  w2, color="#d62728", alpha=0.45, label="β después", hatch="///")

    ax2.set_xticks(xc)
    ax2.set_xticklabels(labels_cats, fontsize=9)
    ax2.set_ylim(0, 0.85)
    ax2.set_ylabel("Valor del peso")
    ax2.set_title("Vectores de pesos por categoría\n(antes vs después de calibración empírica)")
    ax2.legend(fontsize=7, ncol=2)
    ax2.grid(axis="y", alpha=0.3, linestyle=":")
    ax2.spines["top"].set_visible(False)
    ax2.spines["right"].set_visible(False)

    # Anotación del hallazgo clave
    ax2.annotate("β sube de\n0.35-0.40\na 0.48-0.66",
                 xy=(1 + w2*2, 0.657), xytext=(1.6, 0.75),
                 fontsize=8, color="#d62728", fontweight="bold",
                 arrowprops=dict(arrowstyle="->", color="#d62728", lw=1.2))

    fig.text(0.5, -0.03,
             "Calibración empírica: N=78,611 CVEs reales (NVD 2024-2025 + EPSS + CISA KEV) | "
             "Regresión logística: α_emp=0.124, β_emp=0.876 | EPSS es 7× más predictivo que CVSS",
             ha="center", fontsize=8.5, style="italic", color="#555")

    plt.tight_layout()
    plt.savefig(salida_png, dpi=150, bbox_inches="tight")
    print(f"Dashboard guardado en {salida_png}")


def main():
    salida = sys.argv[1] if len(sys.argv) > 1 else "telemetria_calibrada.png"
    generar_dashboard(salida)


if __name__ == "__main__":
    main()
