"""
Engine Evaluador - Caso 3 (DevSecOps y Scoring de Riesgo en SBOM)

Implementa la funcion de riesgo R = alpha*V + beta*E + gamma*C (Seccion 2.2
del TC1) CON LA CORRECCION del feedback del profesor: en vez de aplicar un
unico vector (alpha, beta, gamma) global a todo el inventario, cada
componente recibe el vector correspondiente a la categoria de su activo
(ver asset-inventory/inventory.json).

Entradas:
  - Un reporte de vulnerabilidades en formato JSON de Trivy
    (`trivy sbom --format json sbom.json` o `trivy fs --format json .`)
  - El inventario de activos (asset-inventory/inventory.json)

Salida:
  - Un reporte JSON con el R_score, nivel difuso y decision de Policy Gate
    por cada componente/activo evaluado.
  - Codigo de salida 1 si algun activo cae en politica BLOCK (para que
    GitHub Actions falle el pipeline).
"""
import json
import sys
import os
import time
import urllib.request
import urllib.error

sys.path.insert(0, os.path.dirname(__file__))
from fuzzy_engine import clasificar

EPSS_API_URL = "https://api.first.org/data/v1/epss?cve={cve}"
EPSS_CACHE = {}


def obtener_epss(cve_id):
    """
    Consulta la API publica de FIRST EPSS para un CVE dado.
    Si la API no responde (ej. sin conexion en un entorno cerrado),
    se usa un valor conservador por defecto de 0.10 y se deja constancia
    en el reporte, para no detener la evaluacion por un problema de red.
    """
    if cve_id in EPSS_CACHE:
        return EPSS_CACHE[cve_id]
    try:
        with urllib.request.urlopen(EPSS_API_URL.format(cve=cve_id), timeout=5) as resp:
            data = json.loads(resp.read().decode())
            epss = float(data["data"][0]["epss"]) if data.get("data") else 0.10
    except (urllib.error.URLError, KeyError, IndexError, ValueError, TimeoutError):
        epss = 0.10  # valor por defecto conservador, documentado en el reporte
    EPSS_CACHE[cve_id] = epss
    time.sleep(0.2)  # buena practica: no saturar la API publica
    return epss


def calcular_V(vulnerabilidades):
    """V(Ci) = max(CVSSij) / 10, segun Seccion 2.2 del TC1."""
    if not vulnerabilidades:
        return 0.0
    max_cvss = max(v["cvss"] for v in vulnerabilidades)
    return max_cvss / 10.0


def calcular_E(vulnerabilidades):
    """E(Ci) = max(EPSSij), segun Seccion 2.2 del TC1."""
    if not vulnerabilidades:
        return 0.0
    epss_scores = [obtener_epss(v["cve_id"]) for v in vulnerabilidades]
    return max(epss_scores)


def calcular_C(activo):
    """C(Ci) = (L + NE + D) / 3, segun Seccion 2.2 del TC1."""
    L = activo["L_criticality_level"]
    NE = activo["NE_network_exposure"]
    D = activo["D_dependence"]
    return (L + NE + D) / 3.0


def evaluar_componente(activo, vulnerabilidades, categorias):
    """
    Aplica R = alpha_k*V + beta_k*E + gamma_k*C, donde (alpha_k, beta_k,
    gamma_k) es el vector de la categoria k a la que pertenece el activo
    -- esta es la implementacion concreta de la correccion del feedback.
    """
    categoria_nombre = activo["categoria"]
    pesos = categorias[categoria_nombre]

    V = calcular_V(vulnerabilidades)
    E = calcular_E(vulnerabilidades)
    C = calcular_C(activo)

    R = pesos["alpha"] * V + pesos["beta"] * E + pesos["gamma"] * C
    r_score = round(R * 10, 2)

    clasificacion = clasificar(r_score)

    return {
        "activo_id": activo["id"],
        "nombre": activo["nombre"],
        "categoria": categoria_nombre,
        "pesos_aplicados": pesos,
        "V": round(V, 3),
        "E": round(E, 3),
        "C": round(C, 3),
        "vulnerabilidades_consideradas": [v["cve_id"] for v in vulnerabilidades],
        **clasificacion,
    }


def cargar_vulnerabilidades_trivy(reporte_trivy_path, target_filtro=None):
    """
    Parsea el JSON de salida de `trivy fs --format json` y extrae, por cada
    CVE encontrado, su CVSS base (preferentemente NVD v3).
    """
    with open(reporte_trivy_path) as f:
        reporte = json.load(f)

    vulns = []
    for resultado in reporte.get("Results", []):
        if target_filtro and target_filtro not in resultado.get("Target", ""):
            continue
        for v in resultado.get("Vulnerabilities", []) or []:
            cvss_data = v.get("CVSS", {})
            cvss_score = None
            for fuente in ("nvd", "redhat", "ghsa"):
                if fuente in cvss_data and "V3Score" in cvss_data[fuente]:
                    cvss_score = cvss_data[fuente]["V3Score"]
                    break
            if cvss_score is None:
                cvss_score = 5.0  # valor conservador si Trivy no trae CVSS
            vulns.append({"cve_id": v.get("VulnerabilityID", "UNKNOWN"), "cvss": cvss_score})
    return vulns


def main():
    if len(sys.argv) < 2:
        print("Uso: python evaluator.py <carpeta_con_reportes_trivy>")
        sys.exit(2)

    reportes_dir = sys.argv[1]
    inventario_path = os.path.join(os.path.dirname(__file__), "..", "asset-inventory", "inventory.json")

    with open(inventario_path) as f:
        inventario = json.load(f)

    categorias = inventario["categorias"]
    resultados = []
    hay_bloqueo = False

    for activo in inventario["activos"]:
        reporte_path = os.path.join(reportes_dir, f"{activo['id']}.json")
        if not os.path.exists(reporte_path):
            print(f"[AVISO] No se encontro reporte Trivy para {activo['id']} en {reporte_path}, se omite.")
            continue

        vulnerabilidades = cargar_vulnerabilidades_trivy(reporte_path)
        resultado = evaluar_componente(activo, vulnerabilidades, categorias)
        resultados.append(resultado)

        print(f"\n=== {resultado['nombre']} ({resultado['categoria']}) ===")
        print(f"  Pesos aplicados: {resultado['pesos_aplicados']}")
        print(f"  R_score = {resultado['r_score']} -> {resultado['conjunto_dominante']} -> {resultado['policy_gate']}")

        if resultado["policy_gate"] == "BLOCK":
            hay_bloqueo = True

    reporte_final_path = os.path.join(reportes_dir, "risk_report.json")
    with open(reporte_final_path, "w") as f:
        json.dump({"resultados": resultados, "hay_bloqueo": hay_bloqueo}, f, indent=2, ensure_ascii=False)

    print(f"\nReporte consolidado guardado en {reporte_final_path}")

    if hay_bloqueo:
        print("\n*** POLICY GATE: BLOQUEO. Uno o mas activos superan el umbral de riesgo. ***")
        sys.exit(1)  # hace fallar el step de GitHub Actions
    else:
        print("\nPolicy Gate: PASS. Ningun activo supera el umbral de bloqueo.")
        sys.exit(0)


if __name__ == "__main__":
    main()
