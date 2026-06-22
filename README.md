# Pipeline DevSecOps Inteligente y Quality Gates en la Cadena de Suministro

**CBS07 - Seguridad de Software - Trabajo Calificado N2 - Caso 3**
Universidad Nacional de Ingenieria - Facultad de Ingenieria Electrica y Electronica

Integrantes: Gavino Poma, Maria Olivia / Rau Zavala, Jefferson Pedro

## Escenario de negocio

Una corporacion logistica internacional migra su arquitectura a contenedores
en la nube. Este repositorio implementa, en escala reducida, un pipeline
DevSecOps que genera automaticamente el SBOM de cada microservicio, calcula
un score de riesgo dinamico (R = f(V,E,C)), y bloquea el despliegue si el
riesgo supera un umbral, antes de que el codigo vulnerable llegue a
produccion.

## Correccion respecto al TC1 (feedback del profesor)

El TC1 aplicaba un unico vector de pesos (alpha=0.40, beta=0.35, gamma=0.25)
a todo el inventario por igual. El profesor observo dos problemas:

1. Esos pesos se calibraron una sola vez con un dataset publico externo
   (FIRST/EPSS) y no reflejan necesariamente el comportamiento real de una
   institucion especifica.
2. Un solo R global no captura que distintos tipos de activo (y distintas
   organizaciones, segun su apetito de riesgo) deberian ponderar la
   severidad, la explotabilidad y el contexto de forma distinta.

Este repositorio implementa la correccion en dos partes:

- **`asset-inventory/inventory.json`**: define categorias de activo
  (`expuesto_critico`, `interno`, `aislado_bajo_impacto`), cada una con su
  propio vector (alpha, beta, gamma), justificado segun su exposicion real.
- **`engine/recalibration.py`**: simula la Fase 1 de recalibracion continua,
  reestimando los pesos con datos historicos organizacionales (sinteticos,
  en `data/historical_incidents_sample.json`) y combinandolos con el prior
  cold-start mediante un estimador de shrinkage.

## Arquitectura (3 microservicios)

| Microservicio | Categoria | Exposicion | CVE de demostracion |
|---|---|---|---|
| `services/tracking-api` | expuesto_critico | Internet publico | CVE-2020-14343 (PyYAML, CVSS 9.8) |
| `services/inventory-service` | interno | Red interna | CVE-2022-22817 (Pillow, CVSS 8.1) |
| `services/logging-utility` | aislado_bajo_impacto | Localhost/aislado | CVE-2019-14806 (Werkzeug, CVSS 5.3) |

## Como correrlo localmente

```bash
# 1. Levantar los 3 microservicios
docker compose up --build

# 2. Generar SBOM + reporte de vulnerabilidades con Trivy (requiere Trivy instalado)
./scripts/generate_reports.sh ./reports

# 3. Instalar dependencias del motor evaluador
pip install -r engine/requirements.txt

# 4. Ejecutar el evaluador (aplica R=f(V,E,C) con pesos por categoria)
python engine/evaluator.py ./reports
# Codigo de salida 1 si algun activo cae en BLOCK

# 5. (Opcional) Simular la recalibracion con datos historicos
python engine/recalibration.py

# 6. Detectar typosquatting/dependency confusion en un SBOM
export ANTHROPIC_API_KEY=tu_api_key   # opcional, mejora la deteccion
python ai-agent/typosquatting_detector.py ./reports/tracking-api-sbom.json

# 7. Generar el dashboard comparativo (antes/despues de la correccion)
pip install -r telemetry/requirements.txt
python telemetry/generate_dashboard.py ./reports/risk_report.json ./reports/comparacion.png
```

## Como correrlo en GitHub Actions (pipeline real)

1. Crear el repositorio en GitHub y subir este contenido.
2. (Opcional, recomendado) En **Settings > Secrets and variables > Actions**,
   agregar el secret `ANTHROPIC_API_KEY` para habilitar la capa de
   confirmacion del agente de IA.
3. Hacer push a `main` (o abrir un Pull Request): el workflow
   `.github/workflows/devsecops-pipeline.yml` corre automaticamente.
4. Ir a la pestaña **Actions** del repositorio para ver el resultado en
   vivo. Si algun microservicio supera el umbral de riesgo, el job termina
   en rojo (fallido) y bloquea el merge/deploy -- ese es el momento exacto
   para grabar **"The Break"**.
5. Para grabar **"The Repair"**: actualizar la version de la dependencia
   vulnerable en el `requirements.txt` correspondiente (ej. subir PyYAML a
   una version sin el CVE), hacer push de nuevo, y mostrar como el pipeline
   pasa a verde.

## Estructura del repositorio

```
services/            -> los 3 microservicios (la app vulnerable)
asset-inventory/      -> inventario de activos con categorias y pesos
engine/               -> motor evaluador (R=f(V,E,C)), logica difusa, recalibracion
ai-agent/             -> deteccion de typosquatting/dependency confusion con LLM
data/                 -> datos historicos sinteticos para la recalibracion
telemetry/            -> dashboard comparativo antes/despues
.github/workflows/    -> el pipeline de GitHub Actions
scripts/              -> utilitario para generar SBOM/reportes con Trivy
```
