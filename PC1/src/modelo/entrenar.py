"""Entrenamiento de Isolation Forest solo con tráfico BENIGN del lunes.

El umbral de alerta se calibra sobre el 20 % de validación (también benigno),
nunca con los archivos de evaluación.

Uso (desde PC1/):  python -m src.modelo.entrenar
"""

from __future__ import annotations

import json
from datetime import datetime

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split

from src.procesamiento.caracteristicas import limpiar
from src.procesamiento.dataset import cargar_configuracion, cargar_entrenamiento


def calibrar_umbral(puntajes: np.ndarray, fpr_objetivo: float) -> float:
    """Umbral tal que ~``fpr_objetivo`` de los puntajes benignos queden por debajo.

    En ``decision_function`` valores más bajos = más anómalo, así que el
    umbral es el percentil ``fpr_objetivo * 100`` de los puntajes benignos.
    """
    return float(np.percentile(puntajes, fpr_objetivo * 100))


def entrenar(config: dict | None = None) -> dict:
    """Ejecuta el entrenamiento completo y devuelve los metadatos guardados."""
    config = config or cargar_configuracion()
    caracteristicas = config["caracteristicas"]
    etiqueta = config["datos"]["columna_etiqueta"]
    benigno = config["datos"]["valor_benigno"]
    semilla = config["division"]["semilla"]

    print("\n=== Entrenamiento ===")
    df = limpiar(cargar_entrenamiento(config), caracteristicas, etiqueta)
    df = df[df[etiqueta] == benigno]
    print(f"  Filas BENIGN disponibles: {len(df):,}")

    X = df[caracteristicas].to_numpy()
    X_ent, X_val = train_test_split(
        X, test_size=config["division"]["proporcion_validacion"], random_state=semilla
    )
    print(f"  Entrenamiento: {len(X_ent):,} filas | Validación: {len(X_val):,} filas")

    hiper = dict(config["modelo"])
    modelo = IsolationForest(**hiper)
    modelo.fit(X_ent)

    puntajes_val = modelo.decision_function(X_val)
    fpr_objetivo = config["umbral"]["fpr_objetivo_validacion"]
    umbral = calibrar_umbral(puntajes_val, fpr_objetivo)
    fpr_real = float(np.mean(puntajes_val < umbral))

    print(f"  Umbral calibrado (decision_function): {umbral:.6f}")
    print(f"  FPR objetivo en validación: {fpr_objetivo:.2%} | FPR real: {fpr_real:.4%}")

    dir_modelos = config["rutas"]["modelos"]
    dir_modelos.mkdir(parents=True, exist_ok=True)
    ruta_modelo = dir_modelos / config["archivos_salida"]["modelo"]
    ruta_meta = dir_modelos / config["archivos_salida"]["metadatos"]
    joblib.dump(modelo, ruta_modelo)

    metadatos = {
        "fecha_entrenamiento": datetime.now().isoformat(timespec="seconds"),
        "algoritmo": "IsolationForest",
        "version_scikit_learn": sklearn.__version__,
        "archivo_entrenamiento": config["datos"]["archivo_entrenamiento"],
        "caracteristicas": list(caracteristicas),
        "orden_columnas": {c: i for i, c in enumerate(caracteristicas)},
        "hiperparametros": hiper,
        "division": {
            "proporcion_validacion": config["division"]["proporcion_validacion"],
            "semilla": semilla,
            "filas_entrenamiento": int(len(X_ent)),
            "filas_validacion": int(len(X_val)),
        },
        "umbral": {
            "valor": umbral,
            "regla": "anómalo si decision_function < umbral",
            "fpr_objetivo_validacion": fpr_objetivo,
            "fpr_real_validacion": fpr_real,
        },
        "semillas": {"division": semilla, "modelo": hiper.get("random_state")},
    }
    with open(ruta_meta, "w", encoding="utf-8") as f:
        json.dump(metadatos, f, ensure_ascii=False, indent=2)
    print(f"  Modelo guardado en: {ruta_modelo}")
    print(f"  Metadatos guardados en: {ruta_meta}")
    return metadatos


if __name__ == "__main__":
    entrenar()
