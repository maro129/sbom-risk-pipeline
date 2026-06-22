"""
Utilidad de Logging - Corporacion Logistica Internacional
Categoria de activo: AISLADO_BAJO_IMPACTO (localhost, sin interfaz de red externa)

Este microservicio solo recibe logs de los otros dos servicios y los
escribe a un archivo local. No tiene exposicion de red real: en el
docker-compose esta en una red interna sin puertos publicados.

NOTA ACADEMICA: Usa Werkzeug 0.15.0, afectada por CVE-2019-14806 (CVSS 5.0
- Medio, principalmente Denegacion de Servicio). Se eligio una vulnerabilidad
de severidad mucho menor a las otras dos a proposito, para que la demo
muestre que el mismo "tipo" de hallazgo (dependencia vieja con CVE) produce
una decision de riesgo distinta segun el activo.
"""
from flask import Flask, request, jsonify
import logging

app = Flask(__name__)
logging.basicConfig(filename="app.log", level=logging.INFO)


@app.route("/health")
def health():
    return jsonify({"service": "logging-utility", "status": "up"})


@app.route("/log", methods=["POST"])
def write_log():
    """Recibe un mensaje de log de otro microservicio interno y lo persiste."""
    message = request.json.get("message", "")
    source = request.json.get("source", "desconocido")
    logging.info("[%s] %s", source, message)
    return jsonify({"logged": True})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002)
