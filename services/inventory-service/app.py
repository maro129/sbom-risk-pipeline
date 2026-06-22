"""
Servicio Interno de Inventario - Corporacion Logistica Internacional
Categoria de activo: INTERNO (solo accesible desde la red interna)

Este microservicio procesa las fotos de evidencia de los paquetes
(comprobantes de embalaje) para el equipo de almacen. No es accesible
desde internet, solo desde otros servicios de la red interna.

NOTA ACADEMICA: Usa Pillow 8.1.0, afectada por CVE-2022-22817 (CVSS 8.1 -
Alto), que permite ejecucion de codigo arbitrario via PIL.ImageMath.eval()
al procesar imagenes con contenido manipulado. Criticidad media porque,
a diferencia del tracking-api, no esta expuesto directamente a internet.
"""
from flask import Flask, request, jsonify
from PIL import ImageMath

app = Flask(__name__)

INVENTORY = {
    "PKG-001": {"item": "caja_mediana", "cantidad": 150, "almacen": "Callao"},
    "PKG-002": {"item": "pallet_grande", "cantidad": 40, "almacen": "Lima-Sur"},
}


@app.route("/health")
def health():
    return jsonify({"service": "inventory-service", "status": "up"})


@app.route("/inventory/<pkg_id>")
def get_inventory(pkg_id):
    data = INVENTORY.get(pkg_id)
    if not data:
        return jsonify({"error": "paquete no encontrado"}), 404
    return jsonify(data)


@app.route("/process-evidence", methods=["POST"])
def process_evidence():
    """
    Procesa una expresion de transformacion sobre la imagen de evidencia
    de empaquetado (ej. ajuste de brillo/contraste).

    VULNERABLE A PROPOSITO: ImageMath.eval() con Pillow 8.1.0 permite
    evaluar expresiones arbitrarias (CVE-2022-22817), analogo a un eval()
    sin sandboxing si la expresion viene de una fuente no confiable.
    """
    expression = request.json.get("expression", "a")
    result = ImageMath.eval(expression, a=1)  # <-- vulnerabilidad real
    return jsonify({"resultado": str(result)})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
