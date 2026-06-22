"""
API de Tracking Publico - Corporacion Logistica Internacional
Categoria de activo: EXPUESTO_CRITICO (accesible desde internet)

Este microservicio simula el endpoint publico que usan los clientes finales
para rastrear el estado de sus envios. Por su exposicion a internet, es el
activo de mayor criticidad del inventario.

NOTA ACADEMICA: Este servicio usa intencionalmente PyYAML 5.3.1, version
afectada por CVE-2020-14343 (CVSS 9.8 - Critico), que permite ejecucion de
codigo arbitrario al deserializar YAML no confiable con yaml.load() sin
especificar un Loader seguro. Esto es deliberado para la demostracion
"The Break" del TC2 - en produccion jamas se usaria yaml.load() con
entrada de usuario sin SafeLoader.
"""
from flask import Flask, request, jsonify
import yaml

app = Flask(__name__)

# Base de datos simulada de envios en memoria
SHIPMENTS = {
    "LOG-001": {"status": "en_transito", "origen": "Lima", "destino": "Callao"},
    "LOG-002": {"status": "entregado", "origen": "Arequipa", "destino": "Lima"},
}


@app.route("/health")
def health():
    return jsonify({"service": "tracking-api", "status": "up"})


@app.route("/track/<shipment_id>")
def track(shipment_id):
    """Endpoint publico de rastreo de envios."""
    data = SHIPMENTS.get(shipment_id)
    if not data:
        return jsonify({"error": "envio no encontrado"}), 404
    return jsonify(data)


@app.route("/import-manifest", methods=["POST"])
def import_manifest():
    """
    Endpoint que permite importar un manifiesto de carga en formato YAML.

    VULNERABLE A PROPOSITO: usa yaml.load() en lugar de yaml.safe_load(),
    lo que junto con PyYAML 5.3.1 permite ejecucion remota de codigo (RCE)
    si un atacante envia un YAML malicioso (CVE-2020-14343).
    """
    raw_yaml = request.data.decode("utf-8")
    manifest = yaml.load(raw_yaml, Loader=yaml.Loader)  # <-- vulnerabilidad real
    return jsonify({"manifest_recibido": manifest})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
