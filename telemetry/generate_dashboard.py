"""
Validacion Analitica y Telemetria - Caso 3
Genera un grafico comparativo entre:
  - El modelo ANTES de la correccion (un solo vector de pesos global
    aplicado a todo el inventario, tal como estaba en el TC1 original)
  - El modelo DESPUES de la correccion (vector de pesos diferenciado por
    categoria de activo, segun el feedback del profesor)

Usa los mismos valores de V, E, C medidos por el evaluador para que la
comparacion sea sobre datos reales de la demo, no inventados.
"""
import json
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

PESOS_UNIFORME_ANTES = {"alpha": 0.40, "beta": 0.35, "gamma": 0.25}


def calcular_r_score(V, E, C, pesos):
    R = pesos["alpha"] * V + pesos["beta"] * E + pesos["gamma"] * C
    return round(R * 10, 2)


def generar_comparacion(risk_report_path, salida_png):
    with open(risk_report_path) as f:
        reporte = json.load(f)

    nombres = []
    r_antes = []
    r_despues = []

    for resultado in reporte["resultados"]:
        nombres.append(resultado["nombre"])
        r_antes.append(calcular_r_score(resultado["V"], resultado["E"], resultado["C"], PESOS_UNIFORME_ANTES))
        r_despues.append(resultado["r_score"])

    x = range(len(nombres))
    ancho = 0.35

    fig, ax = plt.subplots(figsize=(9, 5))
    ax.bar([i - ancho / 2 for i in x], r_antes, ancho, label="Antes (pesos uniformes 0.40/0.35/0.25)")
    ax.bar([i + ancho / 2 for i in x], r_despues, ancho, label="Despues (pesos por categoria de activo)")

    ax.axhline(y=7.5, color="red", linestyle="--", linewidth=1, label="Umbral de bloqueo (R=7.5)")
    ax.set_ylabel("R_score (0-10)")
    ax.set_title("Comparacion de R_score: modelo uniforme vs. modelo corregido por categoria")
    ax.set_xticks(list(x))
    ax.set_xticklabels(nombres, rotation=15, ha="right")
    ax.legend()
    ax.set_ylim(0, 10.5)
    fig.tight_layout()
    fig.savefig(salida_png, dpi=150)
    print(f"Grafico guardado en {salida_png}")

    return list(zip(nombres, r_antes, r_despues))


def main():
    if len(sys.argv) < 2:
        print("Uso: python generate_dashboard.py <ruta_risk_report.json> [salida.png]")
        sys.exit(2)

    risk_report_path = sys.argv[1]
    salida_png = sys.argv[2] if len(sys.argv) > 2 else "comparacion_antes_despues.png"

    comparacion = generar_comparacion(risk_report_path, salida_png)
    print("\nResumen:")
    for nombre, antes, despues in comparacion:
        print(f"  {nombre}: antes={antes} -> despues={despues}")


if __name__ == "__main__":
    main()
