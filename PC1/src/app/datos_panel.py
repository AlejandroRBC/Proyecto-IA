"""Lógica del panel sin Streamlit: lectura de CSV, comando de la demo, conteos y gráfica.

Separada de ``panel.py`` para poder probarla con pytest. Nada de aquí carga el
modelo ni llama a ``decision_function``: solo lee los archivos que generan
``evaluar.py`` y ``reproducir_flujos.py``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

RAIZ_PC1 = Path(__file__).resolve().parents[2]
SCRIPT_DEMO = RAIZ_PC1 / "scripts" / "reproducir_flujos.py"
TODAS_LAS_ETIQUETAS = "Todas (muestra aleatoria)"

# Colores (paleta de referencia validada para daltonismo; ver README).
COLOR_SCORE = "#2a78d6"        # azul: puntaje de cada flujo
COLOR_ANOMALO = "#d03b3b"      # rojo de estado crítico: flujos anómalos (con marcador X)
COLOR_HIPOTETICO = "#eda100"   # amarillo: umbral hipotético (lleva etiqueta directa)
COLOR_TINTA = "#52514e"        # texto secundario y umbral oficial
COLOR_REJILLA = "#e4e3df"
COLOR_FONDO = "#fcfcfb"
# Fondo para que las etiquetas de los umbrales no se encimen con los puntos.
ETIQUETA_FONDO = dict(boxstyle="round,pad=0.2", facecolor=COLOR_FONDO, edgecolor="none", alpha=0.9)


def leer_csv(ruta: Path) -> tuple[pd.DataFrame | None, str | None]:
    """Lee un CSV sin lanzar excepciones. Devuelve ``(df, None)`` o ``(None, mensaje)``."""
    try:
        if not Path(ruta).exists():
            return None, f"No existe el archivo `{Path(ruta).name}`."
        df = pd.read_csv(ruta, encoding="utf-8")
        if df.empty:
            return None, f"El archivo `{Path(ruta).name}` está vacío."
        return df, None
    except (pd.errors.EmptyDataError, pd.errors.ParserError, OSError, UnicodeDecodeError) as e:
        return None, f"No se pudo leer `{Path(ruta).name}`: {e}"


def leer_metadatos_modelo(config: dict) -> tuple[dict | None, str | None]:
    """Lee el JSON de metadatos del modelo base (no carga el modelo)."""
    ruta = config["rutas"]["modelos"] / config["archivos_salida"]["metadatos"]
    try:
        with open(ruta, encoding="utf-8") as f:
            return json.load(f), None
    except FileNotFoundError:
        return None, "El modelo no está entrenado todavía: ejecuta `python scripts/ejecutar_experimentos.py`."
    except (OSError, json.JSONDecodeError) as e:
        return None, f"No se pudieron leer los metadatos del modelo: {e}"


def umbral_oficial(metadatos: dict | None) -> float | None:
    if not metadatos:
        return None
    umbral = metadatos.get("umbral")
    return float(umbral["valor"] if isinstance(umbral, dict) else umbral)


def modelo_disponible(config: dict) -> bool:
    rutas = config["rutas"]["modelos"]
    salida = config["archivos_salida"]
    return (rutas / salida["modelo"]).exists() and (rutas / salida["metadatos"]).exists()


def archivos_origen(config: dict) -> list[str]:
    """Los 8 CSV del proyecto que existen en la carpeta de datos crudos."""
    nombres = [config["datos"]["archivo_entrenamiento"], *config["datos"]["archivos_evaluacion"]]
    return [n for n in nombres if (config["rutas"]["datos_crudos"] / n).exists()]


def etiquetas_conocidas(por_tipo: pd.DataFrame | None) -> list[str]:
    """Etiquetas vistas en la evaluación, para el filtro opcional de la demo."""
    if por_tipo is None or "Label" not in por_tipo.columns:
        return []
    return sorted(por_tipo["Label"].astype(str).unique())


def construir_comando(
    archivo: str,
    filas: int,
    intervalo: float,
    semilla: int,
    etiqueta: str | None = None,
) -> list[str]:
    """Comando para ejecutar la demo como subproceso con el mismo intérprete del panel."""
    comando = [
        sys.executable, str(SCRIPT_DEMO),
        "--origen", archivo,
        "--filas", str(int(filas)),
        "--intervalo-segundos", str(float(intervalo)),
        "--semilla", str(int(semilla)),
    ]
    if etiqueta and etiqueta != TODAS_LAS_ETIQUETAS:
        comando += ["--etiqueta", etiqueta]
    return comando


def tiempo_limite(filas: int, intervalo: float) -> int:
    """Segundos máximos para el subproceso: lectura del CSV + pausas + margen."""
    return int(120 + filas * (intervalo + 0.05) * 1.5)


def borrar_historial(config: dict) -> list[str]:
    """Borra alertas.csv y flujos_analizados.csv. Devuelve los nombres borrados."""
    borrados = []
    for clave in ("alertas", "flujos_analizados"):
        ruta = config["rutas"][clave]
        if ruta.exists():
            ruta.unlink()
            borrados.append(ruta.name)
    return borrados


def tabla_por_tipo(por_tipo: pd.DataFrame) -> pd.DataFrame:
    """metricas_por_tipo.csv ordenado por proporción detectada (recall) descendente."""
    tabla = por_tipo.sort_values(["proporcion_detectada", "flujos"], ascending=[False, False])
    return tabla.rename(columns={
        "flujos": "Flujos",
        "detectados_como_anomalos": "Marcados como anómalos",
        "proporcion_detectada": "Proporción detectada",
    }).reset_index(drop=True)


def conteos(historial: pd.DataFrame) -> dict:
    resultado = historial["resultado"].astype(str)
    return {
        "total": int(len(historial)),
        "normales": int((resultado == "NORMAL").sum()),
        "anomalos": int((resultado == "ANOMALO").sum()),
        "no_evaluables": int((resultado == "NO_EVALUABLE").sum()),
    }


def puntajes(historial: pd.DataFrame) -> pd.Series:
    """Puntajes numéricos del historial (los NO_EVALUABLE no tienen puntaje)."""
    return pd.to_numeric(historial["score"], errors="coerce").dropna()


def contar_anomalos_con_umbral(scores: pd.Series, umbral: float) -> int:
    """Misma regla que el detector (anómalo si score < umbral), solo en memoria."""
    return int((scores < umbral).sum())


def figura_puntajes(
    historial: pd.DataFrame,
    umbral: float,
    umbral_hipotetico: float | None = None,
):
    """Puntaje de cada flujo por orden de llegada, con la línea del umbral oficial."""
    datos = historial.copy()
    datos["orden"] = range(1, len(datos) + 1)
    datos["score"] = pd.to_numeric(datos["score"], errors="coerce")
    datos = datos.dropna(subset=["score"])
    anomalos = datos[datos["score"] < umbral]

    fig, ax = plt.subplots(figsize=(10, 4))
    fig.patch.set_facecolor(COLOR_FONDO)
    ax.set_facecolor(COLOR_FONDO)

    ax.plot(datos["orden"], datos["score"], color=COLOR_SCORE, linewidth=1, alpha=0.5, zorder=2)
    ax.scatter(datos["orden"], datos["score"], s=12, color=COLOR_SCORE, zorder=3,
               label="Puntaje del flujo")
    ax.scatter(anomalos["orden"], anomalos["score"], s=70, marker="X", color=COLOR_ANOMALO,
               edgecolors=COLOR_FONDO, linewidths=1.2, zorder=4,
               label=f"Anómalo ({len(anomalos)})")

    ax.axhline(umbral, color=COLOR_TINTA, linestyle="--", linewidth=1.5, zorder=1,
               label="Umbral oficial")
    ax.annotate(f"Umbral oficial {umbral:.4f}", xy=(0, umbral), xycoords=("axes fraction", "data"),
                xytext=(4, 4), textcoords="offset points", ha="left", va="bottom",
                fontsize=9, color=COLOR_TINTA, zorder=5, bbox=ETIQUETA_FONDO)
    if umbral_hipotetico is not None:
        ax.axhline(umbral_hipotetico, color=COLOR_HIPOTETICO, linewidth=2, zorder=1,
                   label="Umbral hipotético")
        ax.annotate(f"Hipotético {umbral_hipotetico:.4f}", xy=(1, umbral_hipotetico),
                    xycoords=("axes fraction", "data"), xytext=(-4, 4), textcoords="offset points",
                    ha="right", va="bottom", fontsize=9, color=COLOR_TINTA, zorder=5,
                    bbox=ETIQUETA_FONDO)

    ax.set_xlabel("Orden de llegada del flujo", color=COLOR_TINTA)
    ax.set_ylabel("score (más bajo = más anómalo)", color=COLOR_TINTA)
    ax.grid(axis="y", color=COLOR_REJILLA, linewidth=0.8)
    ax.set_axisbelow(True)
    for lado in ("top", "right"):
        ax.spines[lado].set_visible(False)
    for lado in ("left", "bottom"):
        ax.spines[lado].set_color(COLOR_REJILLA)
    ax.tick_params(colors=COLOR_TINTA, labelsize=9)
    ax.legend(loc="lower left", fontsize=9, frameon=False, ncol=4, bbox_to_anchor=(0, 1.0))
    fig.tight_layout()
    return fig
