"""Entrena el Random Forest multiclase de familias de ataque con CICIDS2017.

Uso (desde PC1/):
    python scripts/entrenar_clasificador_ataques.py
    python scripts/entrenar_clasificador_ataques.py --max-por-familia 20000   # más rápido

Pasos: carga los 8 CSV (solo las 10 características + Label) → limpieza estándar →
etiquetas agrupadas en familias → submuestreo estratificado (máx. N por familia) →
división 80/20 estratificada → RandomForest → métricas en la parte de prueba.

Salidas:
    modelos/clasificador/      random_forest_ataques.joblib, metadatos_clasificador.json (fuera de git)
    reportes/clasificador/     reporte_clasificacion.csv, matriz_confusion.csv/.png,
                               importancia_caracteristicas.csv, sesion_laboratorio.csv, RESUMEN.md

Nota honesta: la prueba sale del mismo dataset (otro 20 % de los mismos días), así que
mide lo bien que el modelo separa las familias **dentro de CICIDS2017**. En otra red el
rendimiento puede ser mucho peor; por eso también se aplica a la sesión real del
laboratorio guardada (si existe) y se informa lo que salga.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from sklearn.ensemble import RandomForestClassifier  # noqa: E402
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score  # noqa: E402
from sklearn.model_selection import train_test_split  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.clasificacion.modelo_ataques import (  # noqa: E402
    FAMILIAS,
    NOMBRE_METADATOS,
    NOMBRE_MODELO,
    cargar_clasificador,
    familia,
    predecir_familias,
)
from src.procesamiento.caracteristicas import limpiar  # noqa: E402
from src.procesamiento.dataset import cargar_configuracion, cargar_csv  # noqa: E402

SESION_LAB = Path("reportes/sesiones/2026-11-25_escenario_mixto/flujos.csv")

# Paleta: rampa secuencial de un solo tono (azul), clara → oscura.
TINTA, FONDO = "#2b2a27", "#ffffff"
RAMPA_AZUL = ["#f4f8fe", "#d3e3f8", "#a6c6f0", "#6fa3e4", "#2a78d6", "#1d5aa6", "#123d73"]


def cargar_todo(config: dict) -> pd.DataFrame:
    archivos = [config["datos"]["archivo_entrenamiento"], *config["datos"]["archivos_evaluacion"]]
    etiqueta = config["datos"]["columna_etiqueta"]
    partes = []
    for archivo in archivos:
        df = cargar_csv(config, archivo)
        partes.append(limpiar(df, config["caracteristicas"], etiqueta, verbose=False))
    datos = pd.concat(partes, ignore_index=True)
    datos["familia"] = datos[etiqueta].map(familia)
    excluidas = datos["familia"].isna()
    print(f"[datos] {len(datos):,} flujos limpios; excluidos (Infiltration/Heartbleed): {int(excluidas.sum())}")
    return datos[~excluidas].reset_index(drop=True)


def submuestrear(datos: pd.DataFrame, maximo: int, semilla: int) -> pd.DataFrame:
    partes = [g.sample(n=min(len(g), maximo), random_state=semilla) for _, g in datos.groupby("familia")]
    return pd.concat(partes, ignore_index=True)


def figura_matriz(matriz: np.ndarray, clases: list[str]):
    """Matriz de confusión normalizada por fila (cada fila = recall de esa familia)."""
    from matplotlib.colors import LinearSegmentedColormap

    normal = matriz / matriz.sum(axis=1, keepdims=True).clip(min=1)
    mapa = LinearSegmentedColormap.from_list("azul", RAMPA_AZUL)
    fig, ax = plt.subplots(figsize=(7.6, 6.2))
    fig.patch.set_facecolor(FONDO)
    ax.imshow(normal, cmap=mapa, vmin=0, vmax=1)
    for i in range(len(clases)):
        for j in range(len(clases)):
            v = normal[i, j]
            if v < 0.005 and i != j:
                continue
            ax.text(j, i, f"{v:.0%}" if v >= 0.01 else "<1%", ha="center", va="center", fontsize=9,
                    color="#ffffff" if v > 0.55 else TINTA)
    ax.set_xticks(range(len(clases)), clases, rotation=35, ha="right", fontsize=9, color=TINTA)
    ax.set_yticks(range(len(clases)), clases, fontsize=9, color=TINTA)
    ax.set_xlabel("Familia predicha", color=TINTA)
    ax.set_ylabel("Familia real", color=TINTA)
    ax.set_title("Matriz de confusión del Random Forest (prueba, CICIDS2017)", fontsize=11, color=TINTA)
    ax.set_xticks(np.arange(-0.5, len(clases)), minor=True)
    ax.set_yticks(np.arange(-0.5, len(clases)), minor=True)
    ax.grid(which="minor", color=FONDO, linewidth=2)
    ax.tick_params(which="minor", length=0)
    for lado in ax.spines.values():
        lado.set_visible(False)
    fig.tight_layout()
    return fig


def aplicar_a_sesion(config: dict, raiz: Path) -> pd.DataFrame | None:
    """Familias que el Random Forest asigna al tráfico real del laboratorio, por tipo de tráfico."""
    ruta = raiz / SESION_LAB
    clasificador = cargar_clasificador(config)
    if not ruta.exists() or clasificador is None:
        return None
    df = pd.read_csv(ruta)
    pred = predecir_familias(clasificador, df)
    df["familia_rf"] = [p[0] if p else "(no evaluable)" for p in pred]
    tabla = pd.crosstab(df["tipo_trafico"], df["familia_rf"])
    tabla["flujos"] = tabla.sum(axis=1)
    return tabla.reset_index()


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--max-por-familia", type=int, default=40_000)
    p.add_argument("--arboles", type=int, default=200)
    args = p.parse_args()

    config = cargar_configuracion()
    raiz = Path(__file__).resolve().parents[1]
    semilla = int(config["division"]["semilla"])
    caracteristicas = list(config["caracteristicas"])
    t0 = time.time()

    datos = cargar_todo(config)
    disponibles = datos["familia"].value_counts()
    muestra = submuestrear(datos, args.max_por_familia, semilla)
    del datos
    print("[muestra] por familia:\n" + muestra["familia"].value_counts().to_string())

    x_ent, x_pru, y_ent, y_pru = train_test_split(
        muestra[caracteristicas], muestra["familia"], test_size=0.2, stratify=muestra["familia"],
        random_state=semilla)
    modelo = RandomForestClassifier(n_estimators=args.arboles, class_weight="balanced", n_jobs=-1,
                                    random_state=semilla, min_samples_leaf=2)
    modelo.fit(x_ent, y_ent)
    pred = modelo.predict(x_pru)
    clases = [c for c in FAMILIAS if c in set(y_pru)]

    exactitud = accuracy_score(y_pru, pred)
    f1_macro = f1_score(y_pru, pred, average="macro")
    reporte = pd.DataFrame(classification_report(y_pru, pred, labels=clases, output_dict=True, zero_division=0)).T
    reporte = reporte.loc[clases + ["macro avg", "weighted avg"]].rename(columns={"support": "flujos_prueba"})
    matriz = confusion_matrix(y_pru, pred, labels=clases)
    importancia = pd.DataFrame({"caracteristica": caracteristicas, "importancia": modelo.feature_importances_}) \
        .sort_values("importancia", ascending=False)

    carpeta_modelo = Path(config["rutas"]["modelos_clasificador"])
    carpeta_rep = Path(config["rutas"]["reportes_clasificador"])
    carpeta_modelo.mkdir(parents=True, exist_ok=True)
    carpeta_rep.mkdir(parents=True, exist_ok=True)
    joblib.dump(modelo, carpeta_modelo / NOMBRE_MODELO)
    metadatos = {
        "fecha_entrenamiento": datetime.now().isoformat(timespec="seconds"),
        "algoritmo": "RandomForestClassifier",
        "caracteristicas": caracteristicas,
        "familias": clases,
        "hiperparametros": {"n_estimators": args.arboles, "class_weight": "balanced",
                            "min_samples_leaf": 2, "random_state": semilla},
        "max_por_familia": args.max_por_familia,
        "flujos_disponibles_por_familia": {k: int(v) for k, v in disponibles.items()},
        "flujos_entrenamiento": int(len(x_ent)), "flujos_prueba": int(len(x_pru)),
        "exactitud": exactitud, "f1_macro": f1_macro,
    }
    with open(carpeta_modelo / NOMBRE_METADATOS, "w", encoding="utf-8") as f:
        json.dump(metadatos, f, ensure_ascii=False, indent=2)
    with open(carpeta_rep / "metricas_clasificador.json", "w", encoding="utf-8") as f:
        json.dump(metadatos, f, ensure_ascii=False, indent=2)

    reporte.round(4).to_csv(carpeta_rep / "reporte_clasificacion.csv", index_label="familia")
    pd.DataFrame(matriz, index=clases, columns=clases).to_csv(carpeta_rep / "matriz_confusion.csv",
                                                              index_label="real\\predicha")
    importancia.round(4).to_csv(carpeta_rep / "importancia_caracteristicas.csv", index=False)
    fig = figura_matriz(matriz, clases)
    fig.savefig(carpeta_rep / "matriz_confusion.png", dpi=150)
    plt.close(fig)

    sesion = aplicar_a_sesion(config, raiz)
    if sesion is not None:
        sesion.to_csv(carpeta_rep / "sesion_laboratorio.csv", index=False)

    print(f"\nExactitud {exactitud:.4f} | F1 macro {f1_macro:.4f} | {time.time() - t0:.0f} s")
    print(reporte.round(3).to_string())
    print("\nImportancia de las características:\n" + importancia.round(3).to_string(index=False))
    if sesion is not None:
        print("\nFamilias asignadas a la sesión real del laboratorio:\n" + sesion.to_string(index=False))
    print(f"\nModelo en {carpeta_modelo}\nReportes en {carpeta_rep}")


if __name__ == "__main__":
    main()
