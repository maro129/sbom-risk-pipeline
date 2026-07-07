"""
Agente de IA - Deteccion de Dependency Confusion y Typosquatting
Caso 3 (DevSecOps y Scoring de Riesgo en SBOM) - CBS07 UNI TC2

Implementa el "Uso Avanzado de IA" exigido por el Anexo N3 del TC2:
un agente que analiza el SBOM y detecta DOS tipos de anomalias semanticas
que los scanners tradicionales (Trivy/Grype) suelen omitir:

ATAQUE 1 - TYPOSQUATTING:
  Paquetes con nombres muy similares a uno legitimo popular
  (ej. 'reqeusts' vs 'requests', distancia de edicion <= 2).
  Detectado via heuristica de Levenshtein.

ATAQUE 2 - DEPENDENCY CONFUSION:
  Paquetes con nombres identicos a paquetes internos privados
  de la organizacion, publicados maliciosamente en el registro
  publico (PyPI/npm) con numero de version alto para ganar
  precedencia sobre la version interna legitima.
  Detectado comparando el SBOM contra asset-inventory/private-packages.json.

Arquitectura de dos capas:
  1. Heuristica algoritmica (rapida, sin costo de API)
  2. Confirmacion con LLM via OpenRouter/DeepSeek (solo para candidatos
     sospechosos, reduce falsos positivos y genera justificacion en
     lenguaje natural -- patron RAG descrito en Seccion 3.6 del TC1)

Requiere: OPENROUTER_API_KEY configurada como secret en GitHub Actions.
"""
import json
import sys
import os
import time
import urllib.request
import urllib.error

# ---------------------------------------------------------------------------
# CONFIGURACION
# ---------------------------------------------------------------------------

PAQUETES_LEGITIMOS = [
    "flask", "django", "requests", "numpy", "pandas", "pillow", "pyyaml",
    "werkzeug", "urllib3", "boto3", "cryptography", "jinja2", "sqlalchemy",
    "celery", "pytest", "scipy", "matplotlib", "click", "gunicorn",
    "fastapi", "uvicorn", "httpx", "aiohttp", "paramiko", "twisted",
]

PRIVATE_PACKAGES_PATH = os.path.join(
    os.path.dirname(__file__), "..", "asset-inventory", "private-packages.json"
)

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
MODEL = "deepseek/deepseek-chat"


# ---------------------------------------------------------------------------
# CAPA 1 - HEURISTICA
# ---------------------------------------------------------------------------

def distancia_levenshtein(a, b):
    """Distancia de edicion clasica entre dos strings."""
    if len(a) < len(b):
        return distancia_levenshtein(b, a)
    if len(b) == 0:
        return len(a)
    fila_previa = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        fila_actual = [i + 1]
        for j, cb in enumerate(b):
            costo_ins = fila_previa[j + 1] + 1
            costo_del = fila_actual[j] + 1
            costo_sub = fila_previa[j] + (ca != cb)
            fila_actual.append(min(costo_ins, costo_del, costo_sub))
        fila_previa = fila_actual
    return fila_previa[-1]


def detectar_typosquatting(nombres_paquetes, distancia_maxima=2):
    """
    Detecta paquetes con nombres muy similares a paquetes legitimos populares.
    Patron de ataque: 'reqeusts' en vez de 'requests'.
    """
    candidatos = []
    for nombre in nombres_paquetes:
        nombre_lower = nombre.lower()
        if nombre_lower in PAQUETES_LEGITIMOS:
            continue
        for legitimo in PAQUETES_LEGITIMOS:
            d = distancia_levenshtein(nombre_lower, legitimo)
            if 0 < d <= distancia_maxima:
                candidatos.append({
                    "tipo_ataque": "TYPOSQUATTING",
                    "paquete_sbom": nombre,
                    "similar_a": legitimo,
                    "distancia_edicion": d,
                    "descripcion": f"Nombre muy similar al paquete legitimo '{legitimo}' (distancia={d})"
                })
                break
    return candidatos


def detectar_dependency_confusion(nombres_paquetes):
    """
    Detecta paquetes con nombres identicos a paquetes internos privados
    de la organizacion que aparecen en el SBOM como dependencias publicas.
    Patron de ataque: atacante publica 'logistica-core' en PyPI con version
    alta para que el pipeline lo descargue en lugar de la version interna.
    """
    if not os.path.exists(PRIVATE_PACKAGES_PATH):
        print(f"[AVISO] No se encontro {PRIVATE_PACKAGES_PATH}, se omite deteccion de Dependency Confusion.")
        return []

    with open(PRIVATE_PACKAGES_PATH) as f:
        data = json.load(f)

    paquetes_privados = [p.lower() for p in data.get("paquetes_internos_privados", [])]

    candidatos = []
    for nombre in nombres_paquetes:
        if nombre.lower() in paquetes_privados:
            candidatos.append({
                "tipo_ataque": "DEPENDENCY_CONFUSION",
                "paquete_sbom": nombre,
                "similar_a": nombre,
                "distancia_edicion": 0,
                "descripcion": (
                    f"Paquete con nombre identico a un paquete interno privado de la "
                    f"organizacion. Posible ataque de Dependency Confusion: un paquete "
                    f"malicioso con este nombre podria haber sido publicado en PyPI/npm "
                    f"para suplantar la version interna legitima."
                )
            })
    return candidatos


# ---------------------------------------------------------------------------
# CAPA 2 - CONFIRMACION CON LLM
# ---------------------------------------------------------------------------

def confirmar_con_llm(candidatos):
    """
    Consulta a DeepSeek via OpenRouter para confirmar cada candidato
    y generar una justificacion tecnica en lenguaje natural.
    """
    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        print("[AVISO] OPENROUTER_API_KEY no configurada: se omite confirmacion LLM.")
        for c in candidatos:
            c["confirmado_llm"] = None
            c["justificacion_llm"] = "No evaluado (OPENROUTER_API_KEY no configurada)"
        return candidatos

    for c in candidatos:
        if c["tipo_ataque"] == "TYPOSQUATTING":
            prompt = (
                f"Eres un analista de seguridad de cadena de suministro de software. "
                f"En un SBOM aparece el paquete '{c['paquete_sbom']}', cuyo nombre tiene "
                f"distancia de edicion {c['distancia_edicion']} respecto al paquete legitimo "
                f"'{c['similar_a']}'. "
                f"Responde SOLO con JSON: "
                f'{{"es_sospechoso": true/false, "justificacion": "..."}}'
                f" Evalua si es typosquatting real o falso positivo. Sin texto fuera del JSON."
            )
        else:  # DEPENDENCY_CONFUSION
            prompt = (
                f"Eres un analista de seguridad de cadena de suministro de software. "
                f"En el SBOM de una corporacion logistica aparece el paquete '{c['paquete_sbom']}' "
                f"como dependencia publica (PyPI), pero este nombre coincide exactamente con "
                f"un paquete interno privado de la organizacion. "
                f"Responde SOLO con JSON: "
                f'{{"es_sospechoso": true/false, "justificacion": "..."}}'
                f" Evalua si es un posible ataque de Dependency Confusion. Sin texto fuera del JSON."
            )

        payload = json.dumps({
            "model": MODEL,
            "max_tokens": 300,
            "messages": [{"role": "user", "content": prompt}],
        }).encode("utf-8")

        req = urllib.request.Request(
            OPENROUTER_URL,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
                "HTTP-Referer": "https://github.com/maro129/sbom-risk-pipeline",
                "X-Title": "SBOM Risk Pipeline CBS07 UNI TC2",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
                texto = data["choices"][0]["message"]["content"]
        except (urllib.error.URLError, KeyError, IndexError) as e:
            print(f"[AVISO] Error OpenRouter para '{c['paquete_sbom']}': {e}")
            c["confirmado_llm"] = None
            c["justificacion_llm"] = f"Error de red: {e}"
            continue

        try:
            texto_limpio = texto.strip().strip("```json").strip("```").strip()
            juicio = json.loads(texto_limpio)
        except json.JSONDecodeError:
            juicio = {"es_sospechoso": True, "justificacion": texto}

        c["confirmado_llm"] = juicio.get("es_sospechoso")
        c["justificacion_llm"] = juicio.get("justificacion", "")
        time.sleep(0.5)

    return candidatos


# ---------------------------------------------------------------------------
# FUNCION PRINCIPAL
# ---------------------------------------------------------------------------

def analizar_sbom(sbom_cyclonedx_path):
    """Extrae nombres del SBOM y ejecuta ambas detecciones."""
    with open(sbom_cyclonedx_path) as f:
        sbom = json.load(f)

    nombres = [c.get("name", "") for c in sbom.get("components", []) if c.get("name")]
    print(f"[INFO] Analizando {len(nombres)} paquetes en {sbom_cyclonedx_path}")

    candidatos = []
    candidatos += detectar_typosquatting(nombres)
    candidatos += detectar_dependency_confusion(nombres)

    if not candidatos:
        print("[INFO] Sin candidatos sospechosos detectados.")
        return {
            "sbom": sbom_cyclonedx_path,
            "paquetes_analizados": len(nombres),
            "hallazgos": []
        }

    typo = sum(1 for c in candidatos if c["tipo_ataque"] == "TYPOSQUATTING")
    dep_conf = sum(1 for c in candidatos if c["tipo_ataque"] == "DEPENDENCY_CONFUSION")
    print(f"[INFO] Heuristica: {typo} typosquatting, {dep_conf} dependency confusion. Consultando LLM...")

    candidatos = confirmar_con_llm(candidatos)

    return {
        "sbom": sbom_cyclonedx_path,
        "paquetes_analizados": len(nombres),
        "hallazgos": candidatos
    }


def main():
    if len(sys.argv) < 2:
        print("Uso: python typosquatting_detector.py <ruta_sbom_cyclonedx.json>")
        sys.exit(2)

    resultado = analizar_sbom(sys.argv[1])
    print(json.dumps(resultado, indent=2, ensure_ascii=False))

    confirmados = [h for h in resultado["hallazgos"] if h.get("confirmado_llm") is True]
    if confirmados:
        tipos = [h["tipo_ataque"] for h in confirmados]
        print(f"\n[ALERTA] {len(confirmados)} amenaza(s) confirmada(s) por LLM: {tipos}")


if __name__ == "__main__":
    main()
