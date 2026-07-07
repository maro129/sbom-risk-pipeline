# Pipeline DevSecOps Inteligente y Quality Gates en la Cadena de Suministro

**CBS07 - Seguridad de Software - Trabajo Calificado N°2 - Caso 3**  
Universidad Nacional de Ingeniería — Facultad de Ingeniería Eléctrica y Electrónica

**Integrantes:** Gavino Poma, María Olivia / Rau Zavala, Jefferson Pedro  
**Docente:** Mg. Ing. Juan Carlos Tovar — Sección M

---

## Escenario de negocio

Una corporación logística internacional migra su arquitectura a contenedores en la nube. Este repositorio implementa un pipeline DevSecOps que:
1. Genera automáticamente el SBOM (Software Bill of Materials) de cada microservicio
2. Calcula un score de riesgo dinámico **R = f(V,E,C)** con pesos diferenciados por categoría de activo
3. Bloquea el despliegue a Docker Hub si el riesgo supera el umbral (Policy Gate)
4. Detecta ataques semánticos en el SBOM (Typosquatting y Dependency Confusion) mediante un agente de IA

---

## Correcciones respecto al TC1 (feedback del profesor)

El TC1 aplicaba un único vector de pesos global. El profesor identificó dos problemas:

1. **Calibración estática**: los pesos se calcularon una sola vez con un dataset externo. Se corrige con un esquema de dos fases (cold-start + recalibración organizacional via ML).
2. **Un solo R para todo el inventario**: distintas categorías de activo deben tener distintos vectores de pesos.

### Vectores de pesos implementados por categoría

| Categoría | α (CVSS) | β (EPSS) | γ (Contexto) | Justificación |
|---|---|---|---|---|
| `expuesto_critico` | 0.35 | **0.40** | 0.25 | Activo expuesto a internet: β mayor porque EPSS (explotación real) importa más que CVSS teórico |
| `interno` | **0.40** | 0.35 | 0.25 | Vector cold-start NVD/EPSS del TC1. Sin evidencia para inclinar hacia ninguna dimensión |
| `aislado_bajo_impacto` | 0.30 | 0.25 | **0.45** | γ mayor: el contexto real (alcance, exposición) es más determinante que la severidad teórica |

---

## Arquitectura — 3 microservicios

| Microservicio | Categoría | Exposición | CVE de demostración |
|---|---|---|---|
| `services/tracking-api` | `expuesto_critico` | Internet público | CVE-2020-14343 (PyYAML 5.3.1, CVSS 9.8) |
| `services/inventory-service` | `interno` | Red interna | CVE-2022-22817 (Pillow 8.1.0, CVSS 8.1) |
| `services/logging-utility` | `aislado_bajo_impacto` | Localhost/aislado | CVE-2019-14806 (Werkzeug 0.15.0, CVSS 5.3) |

---

## Resultados reales del pipeline (evidencia del TC2)

### The Break (Run #1 — Pillow 8.1.0)
- `inventory-service`: R_score = **8.58** → **BLOCK** ❌
- `tracking-api`: R_score = 5.84 → PASS CON ALERTA (PyYAML CVSS=9.8 pero EPSS=0.060 → falso positivo evitado)
- `logging-utility`: R_score = 4.31 → PASS

### The Repair (Run #2 — Pillow 10.2.0)
- `inventory-service`: R_score = **4.21** → **PASS** ✅ (EPSS bajó de 0.997 a 0.013 tras actualizar)
- Las imágenes se publicaron en Docker Hub: `dmj31/sbom-tracking-api`, `dmj31/sbom-inventory-service`, `dmj31/sbom-logging-utility`

---

## Agente de IA — Detección de amenazas semánticas

El agente (`ai-agent/typosquatting_detector.py`) detecta dos tipos de ataques que los scanners de CVEs (Trivy/Grype) **no pueden detectar**:

### TYPOSQUATTING (tracking-api)
- Paquete detectado: `reqeusts==2.31.0` (transposición de 'u' y 'e' en `requests`)
- Distancia Levenshtein: 2
- Confirmado por DeepSeek (OpenRouter): *"patrón típico de typosquatting que aprovecha errores comunes de escritura"*

### DEPENDENCY CONFUSION (inventory-service)
- Paquete detectado: `logistica-core==9.9.9` (nombre idéntico a paquete interno privado)
- Referencia: `asset-inventory/private-packages.json`
- Confirmado por DeepSeek: *"coincidencia exacta con paquete interno privado; versión 9.9.9 indica intento de ganar precedencia sobre la versión interna legítima"*

---

## Estructura del repositorio

```
services/
├── tracking-api/          → App Flask + PyYAML 5.3.1 (CVE) + sbom-extra-components.json (typosquatting)
├── inventory-service/     → App Flask + Pillow 8.1.0→10.2.0 (CVE) + sbom-extra-components.json (dep.confusion)
└── logging-utility/       → App Flask + Werkzeug 0.15.0 (CVE)

asset-inventory/
├── inventory.json         → Categorías de activo con vectores (α,β,γ) diferenciados
└── private-packages.json  → Lista de paquetes internos privados para detección de Dependency Confusion

engine/
├── evaluator.py           → Motor R=f(V,E,C) con pesos por categoría + integración EPSS real
├── fuzzy_engine.py        → Lógica difusa Mamdani (5 conjuntos trapezoidales)
└── recalibration.py       → Recalibración de α,β,γ con ML (regresión logística + shrinkage)

ai-agent/
└── typosquatting_detector.py → Detección Typosquatting (Levenshtein) + Dependency Confusion + confirmación LLM

data/
└── historical_incidents_sample.json → 20 registros sintéticos para simular la recalibración organizacional

telemetry/
└── generate_dashboard.py  → Gráfica comparativa R_score antes/después de la remediación

.github/workflows/
└── devsecops-pipeline.yml → Pipeline completo: SBOM → Evaluador → Agente IA → Policy Gate → Docker Hub
```

---

## Cómo correrlo localmente

```bash
# 1. Levantar los 3 microservicios
docker compose up --build

# 2. Instalar dependencias del motor evaluador
pip install -r engine/requirements.txt

# 3. Generar SBOM + reporte de vulnerabilidades con Trivy (requiere Trivy instalado)
./scripts/generate_reports.sh ./reports

# 4. Ejecutar el evaluador (R=f(V,E,C) con pesos por categoría)
python engine/evaluator.py ./reports
# Código de salida 1 si algún activo cae en BLOCK

# 5. Simular la recalibración con datos históricos
python engine/recalibration.py

# 6. Detectar typosquatting/dependency confusion en un SBOM
export OPENROUTER_API_KEY=tu_api_key
python ai-agent/typosquatting_detector.py ./reports/tracking-api-sbom.json

# 7. Generar el dashboard comparativo (antes/después)
pip install -r telemetry/requirements.txt
python telemetry/generate_dashboard.py ./reports/risk_report.json ./reports/comparacion.png
```

---

## Cómo correrlo en GitHub Actions

1. Crear los siguientes secrets en **Settings → Secrets and variables → Actions**:

| Secret | Descripción |
|---|---|
| `DOCKERHUB_USERNAME` | Tu usuario de Docker Hub (ej. `dmj31`) |
| `DOCKERHUB_TOKEN` | Personal Access Token de Docker Hub |
| `OPENROUTER_API_KEY` | API key de OpenRouter para el agente de IA |

2. Hacer push a `main` — el workflow corre automáticamente.

3. **The Break**: hacer push con una dependencia vulnerable (ej. `Pillow==8.1.0`) → el job falla en rojo → los pasos de Docker Hub aparecen en gris (skipped).

4. **The Repair**: actualizar la dependencia (ej. `Pillow==10.2.0`) → hacer push → el job pasa a verde → las imágenes se publican en Docker Hub.

---

## Fórmula matemática del modelo

```
R(Cᵢ) = α_k · V(Cᵢ) + β_k · E(Cᵢ) + γ_k · C(Cᵢ)

Donde:
  V(Cᵢ) = max(CVSSᵢⱼ) / 10          → Severidad técnica (NVD/NIST)
  E(Cᵢ) = max(EPSSᵢⱼ)               → Explotabilidad dinámica (FIRST API)
  C(Cᵢ) = (Lᵢ + NEᵢ + Dᵢ) / 3      → Criticidad contextual del activo
  (α_k, β_k, γ_k) = vector de la categoría k del activo
  R_score = R(Cᵢ) × 10 ∈ [0,10]

Umbrales del Policy Gate:
  R_score ≥ 7.5  → BLOCK (hard-fail + detener Docker Hub)
  5.0 ≤ R < 7.5  → PASS CON ALERTA (parche en 7 días)
  R < 5.0        → PASS
```

---

## Secrets configurados

```
DOCKERHUB_USERNAME  → dmj31
DOCKERHUB_TOKEN     → configurado (no expuesto)
OPENROUTER_API_KEY  → configurado (no expuesto)
```

> ⚠️ Nunca subir API keys ni tokens directamente al código. Siempre usar GitHub Secrets.
