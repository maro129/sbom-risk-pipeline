"""
Agente de IA - Deteccion de Dependency Confusion y Typosquatting
Caso 3 (DevSecOps y Scoring de Riesgo en SBOM) - CBS07 UNI TC2

Implementa el "Uso Avanzado de IA" exigido por el Anexo N3 del TC2:
un agente que analiza el SBOM y detecta nombres de paquetes sospechosos
que los scanners tradicionales (Trivy/Grype) suelen omitir, porque estos
no son CVEs conocidos sino anomalias semanticas en los nombres.

Funciona en dos capas:
  1. Heuristica algoritmica (distancia de Levenshtein) contra una lista
     de paquetes legitimos populares -- rapida y sin costo de API.
  2. Confirmacion con LLM via OpenRouter (deepseek/deepseek-chat) solo
     para los candidatos que la heuristica marca como sospechosos --
     reduce falsos positivos y explica el razonamiento en lenguaje
     natural, siguiendo el patron RAG descrito en la Seccion 3.6 del TC1.

Requiere: OPENROUTER_API_KEY configurada como secret en GitHub Actions.
"""
import json
import sys
import os
import time
import urllib.request
import urllib.error

# Lista de paquetes legitimos de alto trafico en PyPI usada como
# referencia para detectar typosquatting.
PAQUETES_LEGITIMOS = [
    "flask", "django", "requests", "numpy", "pandas", "pillow", "pyyaml",
    "werkzeug", "urllib3", "boto3", "cryptography", "jinja2", "sqlalchemy",
    "celery", "pytest", "scipy", "matplotlib", "click", "gunicorn",
    "fastapi", "uvicorn", "httpx", "aiohttp", "paramiko", "twisted",
]

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
MODEL = "deepseek/deepseek-chat"


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


def detectar_candidatos_sospechosos(nombres_paquetes, distancia_maxima=2):
    """
    Capa 1 (heuristica): marca como sospechoso cualquier paquete del SBOM
    cuyo nombre este muy cerca (pero no sea identico) a un paquete legitimo
    conocido -- patron clasico de typosquatting.
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
                    "paquete_sbom": nombre,
                    "similar_a": legitimo,
                    "distancia_edicion": d
                })
                break
    return candidatos


def confirmar_con_llm(candidatos):
    """
    Capa 2 (LLM): confirma via OpenRouter (deepseek/deepseek-chat) si
    cada candidato heuristico es typosquatting real o falso positivo.

    OpenRouter permite acceder a multiples modelos con una sola API key
    y formato compatible con OpenAI. Modelo elegido: deepseek/deepseek-chat
    por su bajo costo y alta precision en tareas de analisis de seguridad.

    Requiere OPENROUTER_API_KEY como secret en GitHub Actions.
    """
    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        print("[AVISO] OPENROUTER_API_KEY no configurada: se omite confirmacion LLM.")
        for c in candidatos:
            c["confirmado_llm"] = None
            c["justificacion_llm"] = "No evaluado (OPENROUTER_API_KEY no configurada)"
        return candidatos

    for c in candidatos:
        prompt = (
            f"Eres un analista de seguridad de cadena de suministro de software. "
            f"En un SBOM aparece el paquete '{c['paquete_sbom']}', cuyo nombre tiene "
            f"distancia de edicion {c['distancia_edicion']} respecto al paquete legitimo "
            f"y ampliamente usado '{c['similar_a']}'. "
            f"Responde SOLO con un JSON de la forma "
            f'{{"es_sospechoso": true, "justificacion": "..."}} '
            f"o "
            f'{{"es_sospechoso": false, "justificacion": "..."}} '
            f"evaluando si es plausiblemente typosquatting/dependency confusion "
            f"o un falso positivo. No incluyas texto fuera del JSON."
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


def analizar_sbom(sbom_cyclonedx_path):
    """Extrae nombres de paquetes del SBOM CycloneDX y ejecuta el agente."""
    with open(sbom_cyclonedx_path) as f:
        sbom = json.load(f)

    nombres = [c.get("name", "") for c in sbom.get("components", []) if c.get("name")]
    print(f"[INFO] Analizando {len(nombres)} paquetes en {sbom_cyclonedx_path}")

    candidatos = detectar_candidatos_sospechosos(nombres)

    if not candidatos:
        print("[INFO] Sin candidatos sospechosos detectados por heuristica.")
        return {
            "sbom": sbom_cyclonedx_path,
            "paquetes_analizados": len(nombres),
            "hallazgos": []
        }

    print(f"[INFO] {len(candidatos)} candidato(s) detectado(s) por heuristica. Consultando LLM...")
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

    sospechosos = [h for h in resultado["hallazgos"] if h.get("confirmado_llm") is True]
    if sospechosos:
        print(f"\n[ALERTA] {len(sospechosos)} paquete(s) confirmado(s) como sospechoso(s) por el LLM.")


if __name__ == "__main__":
    main()
