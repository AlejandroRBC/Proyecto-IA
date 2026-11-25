"""Ejecuta el pipeline completo: verificación de columnas → entrenamiento → evaluación.

Uso (desde PC1/):  python scripts/ejecutar_experimentos.py
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

# Permite importar el paquete ``src`` sin instalarlo.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.modelo.entrenar import entrenar  # noqa: E402
from src.modelo.evaluar import evaluar  # noqa: E402
from src.procesamiento.dataset import cargar_configuracion, verificar_columnas  # noqa: E402


def main() -> None:
    inicio = time.time()
    config = cargar_configuracion()

    print("=== Verificación de columnas ===")
    verificar_columnas(config, config["datos"]["archivo_entrenamiento"])
    for archivo in config["datos"]["archivos_evaluacion"]:
        verificar_columnas(config, archivo)

    meta = entrenar(config)
    m = evaluar(config)

    print("\n=== Resumen final ===")
    print(f"  Umbral: {meta['umbral']['valor']:.6f} "
          f"(FPR en validación: {meta['umbral']['fpr_real_validacion']:.4%})")
    print(f"  Evaluación → Precision {m['precision']:.4f} | Recall {m['recall']:.4f} | "
          f"F1 {m['f1']:.4f} | FPR {m['fpr']:.4f} | ROC-AUC {m['roc_auc']:.4f}")
    print(f"  Tiempo total: {time.time() - inicio:.1f} s")


if __name__ == "__main__":
    main()
