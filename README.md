# Pipeline DevSecOps Inteligente y Quality Gates en la Cadena de Suministro

**CBS07 - Seguridad de Software - Trabajo Calificado N°2 - Caso 3**
Universidad Nacional de Ingeniería — Facultad de Ingeniería Eléctrica y Electrónica

**Integrantes:** Gavino Poma, María Olivia / Rau Zavala, Jefferson Pedro
**Docente:** Mg. Ing. Juan Carlos Tovar — Sección M

---

## Escenario de negocio

Una corporación logística internacional migra su arquitectura a contenedores en la nube. Este repositorio implementa un pipeline DevSecOps que:
1. Genera automáticamente el SBOM (Software Bill of Materials) de cada microservicio
2. Calcula un score de riesgo dinámico **R = f(V,E,C)** con pesos calibrados empíricamente por categoría de activo
3. Bloquea el despliegue a Docker Hub si el riesgo supera el umbral (Policy Gate)
4. Detecta ataques semánticos en el SBOM (Typosquatting y Dependency Confusion) mediante un agente de IA

---

## Calibración empírica de los pesos α, β, γ (Corrección TC1 — feedback del profesor)

El feedback del profesor señaló que los pesos originales (0.40, 0.35, 0.25) eran subjetivos. Se calibraron empíricamente mediante regresión logística binaria:

### Dataset de calibración
| Parámetro | Valor |
|---|---|
| Fuentes | NVD JSON 2024-2025 + EPSS (FIRST) + CISA KEV 2024-2025 |
| N total (CVEs con CVSS + EPSS) | **78,611** |
| y=1 (explotación confirmada en KEV) | 347 (0.44%) |
| y=0 (no confirmados) | 78,264 |
| Exclusión de 2026 | Data censoring — CVEs recientes sin tiempo suficiente para aparecer en KEV |

### Resultado de la regresión logística
```
α_emp (CVSS) = 0.124   β_emp (EPSS) = 0.876
```
**Hallazgo:** EPSS es 7× más predictivo que CVSS para explotación real confirmada.
Coherente con el caso empírico del TC2: PyYAML (CVSS=9.8, EPSS=0.060 → PASS) vs Pillow (CVSS=9.8, EPSS=0.997 → BLOCK).

### Vectores de pesos finales por categoría

| Categoría | α (CVSS) | β (EPSS) | γ (Contexto) | Justificación γ |
|---|---|---|---|---|
| `expuesto_critico` | 0.093 | 0.657 | **0.250** | NIST SP 800-190 + OWASP A03:2025: C(Ci) distingue si el paquete comprometido afecta a un contenedor en internet o uno interno — distinción que CVSS/EPSS no pueden hacer |
| `interno` | 0.093 | 0.657 | **0.250** | Prior cold-start. Diferenciación con expuesto_critico capturada por NE_i=0.5 en el valor del activo |
| `aislado_bajo_impacto` | 0.068 | 0.482 | **0.450** | γ mayor porque para activos aislados (NE=0.1) el contexto real es más determinante que la severidad teórica |

**Nota sobre γ:** La variable C(Ci) = (L + NE + D)/3 es información organizacional que no existe en ninguna base de datos pública. Por diseño, γ solo puede calibrarse con datos propios de la organización, que es exactamente el propósito de la Fase 1 en `engine/recalibration.py`.

---

## Arquitectura — 3 microservicios

| Microservicio | Categoría | Exposición | CVE de demostración |
|---|---|---|---|
| `services/tracking-api` | `expuesto_critico` | Internet público | CVE-2020-14343 (PyYAML 5.3.1, CVSS 9.8, EPSS 0.060) |
| `services/inventory-service` | `interno` | Red interna | CVE libwebp (Pillow 8.1.0, CVSS 9.8, EPSS 0.997) |
| `services/logging-utility` | `aislado_bajo_impacto` | Localhost/aislado | CVE-2019-14806 (Werkzeug 0.15.0, CVSS 5.3) |

---

## Resultados reales del pipeline (con pesos calibrados empíricamente)

### The Break (Run #1 — Pillow 8.1.0, EPSS=0.997)
| Microservicio | V | E (EPSS) | C | R_score | Policy Gate |
|---|---|---|---|---|---|
| API Tracking Público (PyYAML) | 0.980 | 0.060 | 0.867 | **3.47** | PASS |
| Serv. Inventario (Pillow 8.1.0) | 0.750 | **0.997** | 0.467 | **8.42** | **BLOCK ❌** |
| Utilidad Logging (Werkzeug) | 0.750 | 0.555 | 0.150 | **3.86** | PASS |

### The Repair (Run #2 — Pillow 10.2.0, EPSS=0.013)
| Microservicio | R_score | Policy Gate |
|---|---|---|
| API Tracking Público | 3.47 | PASS ✅ |
| Serv. Inventario (Pillow 10.2.0) | **1.95** | PASS ✅ |
| Utilidad Logging | 3.86 | PASS ✅ |

**Observación clave:** PyYAML tiene CVSS=9.8 (idéntico a Pillow) pero EPSS=0.060 → R_score=3.47 (PASS). Pillow tiene EPSS=0.997 → R_score=8.42 (BLOCK). Los pesos calibrados empíricamente capturan correctamente que EPSS es el predictor dominante.

---

## Agente de IA — Detección de amenazas semánticas

| Microservicio | Tipo de Ataque | Paquete Detectado | LLM Confirmó |
|---|---|---|---|
| tracking-api | **TYPOSQUATTING** | reqeusts==2.31.0 (dist. Levenshtein=2) | SÍ (DeepSeek) |
| inventory-service | **DEPENDENCY_CONFUSION** | logistica-core==9.9.9 | SÍ (DeepSeek) |
| logging-utility | NINGUNO | — | N/A |

---

## Estructura del repositorio

```
services/            → los 3 microservicios (app vulnerable)
asset-inventory/     → inventario con categorías y vectores (α_k,β_k,γ_k) calibrados
engine/              → evaluador R=f(V,E,C), lógica difusa, recalibración ML
ai-agent/            → detección Typosquatting + Dependency Confusion (DeepSeek via OpenRouter)
data/                → registros sintéticos organizacionales para recalibración Fase 1
telemetry/           → dashboard comparativo antes/después
.github/workflows/   → pipeline GitHub Actions completo
```

---

## Cómo correrlo en GitHub Actions

1. Configurar secrets en **Settings → Secrets → Actions:**
   - `DOCKERHUB_USERNAME` → dmj31
   - `DOCKERHUB_TOKEN` → Personal Access Token Docker Hub
   - `OPENROUTER_API_KEY` → API key de OpenRouter (DeepSeek)
2. Hacer push a `main` → el workflow corre automáticamente
3. **The Break:** con Pillow 8.1.0 → job falla en rojo, pasos de Docker Hub en gris (skipped)
4. **The Repair:** cambiar a Pillow 10.2.0 → push → job pasa a verde, imágenes publicadas en Docker Hub

---

## Fórmula matemática del modelo

```
R(Cᵢ) = α_k · V(Cᵢ) + β_k · E(Cᵢ) + γ_k · C(Cᵢ)

Donde:
  V(Cᵢ) = max(CVSSᵢⱼ) / 10        → Severidad técnica (NVD/NIST)
  E(Cᵢ) = max(EPSSᵢⱼ)             → Explotabilidad dinámica (FIRST API real)
  C(Cᵢ) = (Lᵢ + NEᵢ + Dᵢ) / 3    → Criticidad contextual del activo
  (α_k, β_k, γ_k) = vector de la categoría k (calibrado empiricamente)
  R_score = R(Cᵢ) × 10 ∈ [0,10]

Calibración empírica (N=78,611 CVEs, NVD 2024-2025 + EPSS + CISA KEV):
  α_emp=0.124, β_emp=0.876 → EPSS es 7× más predictivo que CVSS

Umbrales del Policy Gate:
  R_score ≥ 7.5  → BLOCK (hard-fail + detener Docker Hub)
  5.0 ≤ R < 7.5  → PASS CON ALERTA
  R < 5.0        → PASS
```

---

## Repositorio

`github.com/maro129/sbom-risk-pipeline`

> ⚠️ Nunca subir API keys ni tokens directamente al código. Siempre usar GitHub Secrets.
