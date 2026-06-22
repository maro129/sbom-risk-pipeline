#!/bin/bash
# Genera el SBOM (CycloneDX) y el reporte de vulnerabilidades de cada
# microservicio usando Trivy. Se usa tanto en local como dentro del
# pipeline de GitHub Actions.
#
# Uso: ./scripts/generate_reports.sh <carpeta_de_salida>

set -e

OUT_DIR="${1:-./reports}"
mkdir -p "$OUT_DIR"

SERVICIOS=("tracking-api" "inventory-service" "logging-utility")

for SERVICIO in "${SERVICIOS[@]}"; do
    echo ">>> Generando SBOM para $SERVICIO ..."
    trivy fs --format cyclonedx --output "$OUT_DIR/${SERVICIO}-sbom.json" "./services/${SERVICIO}"

    echo ">>> Escaneando vulnerabilidades de $SERVICIO ..."
    trivy fs --format json --output "$OUT_DIR/${SERVICIO}.json" "./services/${SERVICIO}"
done

echo ">>> Reportes generados en $OUT_DIR"
