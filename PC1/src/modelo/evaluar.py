"""Evaluación del modelo entrenado sobre los archivos de martes a viernes.

Estos archivos se usan solo aquí, una vez: no se ajusta nada con ellos.
BENIGN = normal (0); cualquier otro valor de Label = anómalo (1).

Uso (desde PC1/):  python -m src.modelo.evaluar
"""

from __future__ import annotations

import json

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import (
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from src.procesamiento.caracteristicas import limpiar
from src.procesamiento.dataset import cargar_configuracion, cargar_evaluacion


def calcular_metricas(y_real: np.ndarray, y_pred: np.ndarray) -> dict:
    """Precision, Recall, F1, FPR y matriz de confusión (1 = anómalo)."""
    vn, fp, fn, vp = confusion_matrix(y_real, y_pred, labels=[0, 1]).ravel()
    return {
        "precision": precision_score(y_real, y_pred, zero_division=0),
        "recall": recall_score(y_real, y_pred, zero_division=0),
        "f1": f1_score(y_real, y_pred, zero_division=0),
        "fpr": fp / (fp + vn) if (fp + vn) else 0.0,
        "verdaderos_negativos": int(vn),
        "falsos_positivos": int(fp),
        "falsos_negativos": int(fn),
        "verdaderos_positivos": int(vp),
        "total_flujos": int(len(y_real)),
    }


def metricas_por_tipo(etiquetas: pd.Series, y_pred: np.ndarray) -> pd.DataFrame:
    """Proporción marcada como anómala por cada valor de Label (solo análisis).

    Para los ataques es el recall; para BENIGN es la tasa de falsos positivos.
    """
    tabla = (
        pd.DataFrame({"Label": etiquetas.to_numpy(), "anomalo": y_pred})
        .groupby("Label")["anomalo"]
        .agg(flujos="size", detectados_como_anomalos="sum")
        .reset_index()
    )
    tabla["proporcion_detectada"] = tabla["detectados_como_anomalos"] / tabla["flujos"]
    return tabla.sort_values("flujos", ascending=False).reset_index(drop=True)


def guardar_histograma(puntajes, y_real, umbral, ruta) -> None:
    """Histograma de puntajes normal vs. anómalo con la línea del umbral."""
    fig, ax = plt.subplots(figsize=(9, 5))
    bins = np.linspace(np.percentile(puntajes, 0.1), np.percentile(puntajes, 99.9), 120)
    ax.hist(puntajes[y_real == 0], bins=bins, alpha=0.6, density=True, label="BENIGN")
    ax.hist(puntajes[y_real == 1], bins=bins, alpha=0.6, density=True, label="Ataque")
    ax.axvline(umbral, color="black", linestyle="--", label=f"Umbral = {umbral:.4f}")
    ax.set_xlabel("decision_function (más bajo = más anómalo)")
    ax.set_ylabel("Densidad")
    ax.set_title("Distribución de puntajes en evaluación")
    ax.legend()
    fig.tight_layout()
    fig.savefig(ruta, dpi=120)
    plt.close(fig)


def evaluar(config: dict | None = None) -> dict:
    """Ejecuta la evaluación completa y devuelve las métricas globales."""
    config = config or cargar_configuracion()
    caracteristicas = config["caracteristicas"]
    etiqueta = config["datos"]["columna_etiqueta"]
    benigno = config["datos"]["valor_benigno"]

    dir_modelos = config["rutas"]["modelos"]
    modelo = joblib.load(dir_modelos / config["archivos_salida"]["modelo"])
    with open(dir_modelos / config["archivos_salida"]["metadatos"], encoding="utf-8") as f:
        metadatos = json.load(f)
    if metadatos["caracteristicas"] != list(caracteristicas):
        raise ValueError("Las características de la configuración no coinciden con las del modelo guardado.")
    umbral = metadatos["umbral"]["valor"]

    print("\n=== Evaluación ===")
    df = limpiar(cargar_evaluacion(config), caracteristicas, etiqueta)

    puntajes = modelo.decision_function(df[caracteristicas].to_numpy())
    y_pred = (puntajes < umbral).astype(int)
    y_real = (df[etiqueta] != benigno).astype(int).to_numpy()

    metricas = calcular_metricas(y_real, y_pred)
    metricas["umbral"] = umbral
    # Independiente del umbral: mide qué tan bien el puntaje ordena ataques vs. normal.
    # Solo se reporta; no se usa para ajustar nada.
    metricas["roc_auc"] = float(roc_auc_score(y_real, -puntajes))
    por_tipo = metricas_por_tipo(df[etiqueta], y_pred)

    dir_reportes = config["rutas"]["reportes"]
    dir_figuras = config["rutas"]["figuras"]
    dir_figuras.mkdir(parents=True, exist_ok=True)
    pd.DataFrame([metricas]).to_csv(dir_reportes / config["archivos_salida"]["metricas"], index=False)
    por_tipo.to_csv(dir_reportes / config["archivos_salida"]["metricas_por_tipo"], index=False)
    guardar_histograma(puntajes, y_real, umbral, dir_figuras / "distribucion_puntajes.png")

    print(f"  Precision: {metricas['precision']:.4f} | Recall: {metricas['recall']:.4f} | "
          f"F1: {metricas['f1']:.4f} | FPR: {metricas['fpr']:.4f} | ROC-AUC: {metricas['roc_auc']:.4f}")
    print(f"  Matriz de confusión: VN={metricas['verdaderos_negativos']:,} "
          f"FP={metricas['falsos_positivos']:,} FN={metricas['falsos_negativos']:,} "
          f"VP={metricas['verdaderos_positivos']:,}")
    print("  Proporción detectada por tipo de Label:")
    with pd.option_context("display.width", 120):
        print(por_tipo.to_string(index=False))
    print(f"  Reportes guardados en: {dir_reportes}")
    return metricas


if __name__ == "__main__":
    evaluar()
