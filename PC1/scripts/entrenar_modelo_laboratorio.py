"""Entrena el modelo de laboratorio con flujos capturados en vivo y lo compara con el modelo base.

Antes de correrlo:
  1. En PC1, capturar una sesión con tráfico normal y los escenarios de PC2:
        python scripts/capturar_en_vivo.py --todo-el-trafico
  2. Copiar PC2/registros/escenarios_ejecutados.csv de PC2 a
        PC1/datos/laboratorio/escenarios_pc2.csv   (rutas.escenarios_pc2)

Ejemplos (desde PC1/):
    python scripts/entrenar_modelo_laboratorio.py
    python scripts/entrenar_modelo_laboratorio.py --flujos sesion1.csv sesion2.csv
    python scripts/entrenar_modelo_laboratorio.py --escenarios-pc2 ruta/escenarios.csv --ip-pc2 192.168.1.10

No modifica el modelo base. Guarda en modelos/laboratorio/ y reportes/laboratorio/.
Para usarlo en vivo:  python scripts/capturar_en_vivo.py --modelo laboratorio
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

import joblib
import sklearn

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.modelo.detector import cargar_detector, rutas_modelo  # noqa: E402
from src.modelo.laboratorio import (  # noqa: E402
    NORMAL,
    ErrorDatosLaboratorio,
    cargar_escenarios_pc2,
    cargar_flujos_capturados,
    entrenar_y_evaluar,
    etiquetar_flujos,
)
from src.procesamiento.dataset import cargar_configuracion  # noqa: E402


def leer_argumentos(config: dict) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Entrena el modelo de laboratorio con flujos capturados.")
    p.add_argument("--flujos", nargs="+", default=[str(config["rutas"]["flujos_capturados"])],
                   help="Uno o más CSV de flujos capturados (por defecto rutas.flujos_capturados).")
    p.add_argument("--escenarios-pc2", default=str(config["rutas"]["escenarios_pc2"]),
                   help="CSV de escenarios copiado desde PC2.")
    p.add_argument("--ip-pc2", default=(config.get("captura") or {}).get("ip_pc2"),
                   help="IP de PC2, solo para escenarios de un CSV antiguo sin ip_origen.")
    p.add_argument("--sin-escenarios", action="store_true",
                   help="Entrenar sin CSV de PC2: TODO se considera normal (solo si no hubo ataques).")
    return p.parse_args()


def main() -> None:
    config = cargar_configuracion()
    lab = config.get("laboratorio") or {}
    args = leer_argumentos(config)

    print("\n=== Modelo de laboratorio ===")
    try:
        flujos = cargar_flujos_capturados(args.flujos, config["caracteristicas"])
        if args.sin_escenarios:
            escenarios = cargar_escenarios_pc2(None)
            print("  Sin escenarios de PC2: todos los flujos se consideran normales.")
        else:
            if not Path(args.escenarios_pc2).exists():
                sys.exit(f"No se encontró el CSV de escenarios de PC2: {args.escenarios_pc2}\n"
                         "Cópialo desde PC2 (registros/escenarios_ejecutados.csv) o usa --sin-escenarios "
                         "si en la captura no hubo ataques.")
            escenarios = cargar_escenarios_pc2(args.escenarios_pc2)
            print(f"  Escenarios de PC2: {len(escenarios)} "
                  f"({', '.join(f'{k}={v}' for k, v in escenarios['tipo_escenario'].value_counts().items())})")
        etiquetas = etiquetar_flujos(flujos, escenarios, lab.get("tipos_ataque", []),
                                     lab.get("tolerancia_segundos", 5), args.ip_pc2)
        try:
            base = cargar_detector(config, "base")
        except FileNotFoundError:
            base = None
            print("  (Modelo base no encontrado: no se hará la comparación.)")
        res = entrenar_y_evaluar(config, flujos, etiquetas, base)
    except ErrorDatosLaboratorio as e:
        sys.exit(f"No se pudo entrenar: {e}")

    ruta_modelo, ruta_meta = rutas_modelo(config, "laboratorio")
    ruta_modelo.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(res["modelo"], ruta_modelo)
    caracteristicas = list(config["caracteristicas"])
    metadatos = {
        "fecha_entrenamiento": datetime.now().isoformat(timespec="seconds"),
        "algoritmo": "IsolationForest",
        "version_scikit_learn": sklearn.__version__,
        "origen_datos": {
            "flujos_capturados": [Path(f).name for f in args.flujos],
            "escenarios_pc2": None if args.sin_escenarios else Path(args.escenarios_pc2).name,
            "conteo_etiquetas": res["conteo_etiquetas"],
            "tolerancia_segundos": lab.get("tolerancia_segundos", 5),
            "entrenado_solo_con": NORMAL,
        },
        "caracteristicas": caracteristicas,
        "orden_columnas": {c: i for i, c in enumerate(caracteristicas)},
        "hiperparametros": res["hiperparametros"],
        "division": {
            "proporcion_validacion": config["division"]["proporcion_validacion"],
            "semilla": config["division"]["semilla"],
            "filas_entrenamiento": res["filas_entrenamiento"],
            "filas_validacion": res["filas_validacion"],
        },
        "umbral": {
            "valor": res["umbral"],
            "regla": "anómalo si decision_function < umbral",
            "fpr_objetivo_validacion": config["umbral"]["fpr_objetivo_validacion"],
            "fpr_real_validacion": res["fpr_real_validacion"],
        },
    }
    with open(ruta_meta, "w", encoding="utf-8") as f:
        json.dump(metadatos, f, ensure_ascii=False, indent=2)

    dir_reportes = config["rutas"]["reportes_laboratorio"]
    dir_reportes.mkdir(parents=True, exist_ok=True)
    res["metricas"].to_csv(dir_reportes / "metricas.csv", index=False)
    res["metricas_por_tipo"].to_csv(dir_reportes / "metricas_por_tipo.csv", index=False)

    print("\n=== Evaluación (validación normal + ataques de PC2) ===")
    columnas = ["modelo", "precision", "recall", "f1", "fpr", "roc_auc", "total_flujos"]
    print(res["metricas"][columnas].to_string(index=False, float_format=lambda v: f"{v:.4f}"))
    print("\nProporción marcada como anómala por tipo (en 'normal' es la tasa de falsos positivos):")
    tabla = res["metricas_por_tipo"].pivot(index="Label", columns="modelo", values="proporcion_detectada")
    tabla.insert(0, "flujos", res["metricas_por_tipo"].groupby("Label")["flujos"].first())
    print(tabla.to_string(float_format=lambda v: f"{v:.1%}"))
    if not any(lbl != NORMAL for lbl in res["conteo_etiquetas"]):
        print("\nAviso: no hubo flujos de ataque, así que el recall no se puede medir.")
    print(f"\n  Modelo:   {ruta_modelo}\n  Metadatos: {ruta_meta}\n  Reportes: {dir_reportes}")
    print("  Usarlo en vivo: python scripts/capturar_en_vivo.py --modelo laboratorio")


if __name__ == "__main__":
    main()
