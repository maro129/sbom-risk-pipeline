"""
Agente de IA - Deteccion de Dependency Confusion y Typosquatting
Caso 3 (DevSecOps y Scoring de Riesgo en SBOM)

Implementa el "Uso de IA" exigido por el Anexo N3 del TC2: un agente que
analiza el SBOM y detecta nombres de paquetes sospechosos que los
scanners tradicionales (Trivy/Grype) suelen omitir, porque estos no son
CVEs conocidos sino anomalias semanticas en los nombres.

Funciona en dos capas:
  1. Heuristica algoritmica (distancia de edicion) contra una lista de
     paquetes legitimos populares -- rapida y sin costo de API.
  2. Confirmacion con LLM (Claude) solo para los candidatos que la
     heuristica marca como sospechosos -- reduce falsos positivos y
     explica el razonamiento en lenguaje natural, como pide el patron
     RAG descrito en la Seccion 3.6 del TC1.
"""
import json
import sys
import os

# Lista reducida de paquetes legitimos de alto trafico en PyPI, usada como
# referencia para detectar typosquatting (en un escenario real se usaria
# el indice completo de PyPI/npm).
PAQUETES_LEGITIMOS = [
    "flask", "django", "requests", "numpy", "pandas", "pillow", "pyyaml",
    "werkzeug", "urllib3", "boto3", "cryptography", "jinja2", "sqlalchemy",
    "celery", "pytest", "scipy", "matplotlib", "click", "gunicorn",
]


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
    conocido -- el patron clasico de typosquatting (ej. 'reqeusts' en vez
    de 'requests').
    """
    candidatos = []
    for nombre in nombres_paquetes:
        nombre_lower = nombre.lower()
        if nombre_lower in PAQUETES_LEGITIMOS:
            continue  # es exactamente un paquete legitimo, no hay nada que marcar
        for legitimo in PAQUETES_LEGITIMOS:
            d = distancia_levenshtein(nombre_lower, legitimo)
            if 0 < d <= distancia_maxima:
                candidatos.append({"paquete_sbom": nombre, "similar_a": legitimo, "distancia_edicion": d})
                break
    return candidatos


def confirmar_con_llm(candidatos):
    """
    Capa 2 (LLM): para cada candidato heuristico, se le pide a Claude que
    razone si es plausible que sea typosquatting/dependency confusion o
    si es un falso positivo (ej. un paquete legitimo con nombre
    parecido por casualidad, como un fork con sufijo).

    Requiere la variable de entorno ANTHROPIC_API_KEY configurada como
    secret en GitHub Actions. Si no esta configurada, se omite esta capa
    y se reporta solo el resultado de la heuristica (con una advertencia).
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("[AVISO] ANTHROPIC_API_KEY no configurada: se omite la capa de confirmacion con LLM.")
        for c in candidatos:
            c["confirmado_llm"] = None
            c["justificacion_llm"] = "No evaluado (API key no configurada)"
        return candidatos

    try:
        import anthropic
    except ImportError:
        print("[AVISO] Paquete 'anthropic' no instalado: se omite la capa de confirmacion con LLM.")
        for c in candidatos:
            c["confirmado_llm"] = None
            c["justificacion_llm"] = "No evaluado (SDK no instalado)"
        return candidatos

    client = anthropic.Anthropic(api_key=api_key)

    for c in candidatos:
        prompt = (
            f"Eres un analista de seguridad de cadena de suministro de software. "
            f"En un SBOM aparece el paquete '{c['paquete_sbom']}', cuyo nombre es muy "
            f"similar (distancia de edicion {c['distancia_edicion']}) al paquete legitimo "
            f"y ampliamente usado '{c['similar_a']}'. "
            f"Responde SOLO con un JSON de la forma "
            f'{{"es_sospechoso": true/false, "justificacion": "..."}} '
            f"evaluando si esto es plausiblemente un caso de typosquatting o "
            f"dependency confusion, o si es razonablemente un falso positivo."
        )
        respuesta = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=300,
            messages=[{"role": "user", "content": prompt}],
        )
        texto = "".join(b.text for b in respuesta.content if hasattr(b, "text"))
        try:
            texto_limpio = texto.strip().strip("```json").strip("```").strip()
            juicio = json.loads(texto_limpio)
        except json.JSONDecodeError:
            juicio = {"es_sospechoso": True, "justificacion": texto}

        c["confirmado_llm"] = juicio.get("es_sospechoso")
        c["justificacion_llm"] = juicio.get("justificacion", "")

    return candidatos


def analizar_sbom(sbom_cyclonedx_path):
    """Extrae los nombres de paquetes de un SBOM CycloneDX y ejecuta el agente."""
    with open(sbom_cyclonedx_path) as f:
        sbom = json.load(f)

    nombres = [c.get("name", "") for c in sbom.get("components", []) if c.get("name")]
    candidatos = detectar_candidatos_sospechosos(nombres)

    if not candidatos:
        return {"sbom": sbom_cyclonedx_path, "paquetes_analizados": len(nombres), "hallazgos": []}

    candidatos = confirmar_con_llm(candidatos)
    return {"sbom": sbom_cyclonedx_path, "paquetes_analizados": len(nombres), "hallazgos": candidatos}


def main():
    if len(sys.argv) < 2:
        print("Uso: python typosquatting_detector.py <ruta_sbom_cyclonedx.json>")
        sys.exit(2)

    resultado = analizar_sbom(sys.argv[1])
    print(json.dumps(resultado, indent=2, ensure_ascii=False))

    sospechosos_confirmados = [h for h in resultado["hallazgos"] if h.get("confirmado_llm") is not False]
    if sospechosos_confirmados:
        print(f"\n[ALERTA] {len(sospechosos_confirmados)} paquete(s) sospechoso(s) detectado(s).")


if __name__ == "__main__":
    main()
