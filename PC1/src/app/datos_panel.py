"""Lógica del panel sin Streamlit: lectura de CSV, comando de la demo, conteos y gráfica.

Separada de ``panel.py`` para poder probarla con pytest. Nada de aquí carga el
modelo ni llama a ``decision_function``: solo lee los archivos que generan
``evaluar.py`` y ``reproducir_flujos.py``.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
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
    """Borra alertas.csv, flujos_analizados.csv e incidentes.csv. Devuelve los nombres borrados."""
    borrados = []
    for clave in ("alertas", "flujos_analizados", "incidentes"):
        ruta = config["rutas"].get(clave)
        if ruta is not None and ruta.exists():
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


# ---------------------------------------------------------------------------
# Monitoreo en vivo (scripts/capturar_en_vivo.py)
# ---------------------------------------------------------------------------
ORIGEN_CAPTURA = "captura_en_vivo"
COLUMNAS_VIVO = ["fecha_hora", "ip_origen", "puerto_origen", "ip_destino", "puerto_destino",
                 "score", "resultado", "tipo_ataque"]


def leer_estado_captura(ruta: Path) -> dict | None:
    """Lee el JSON de estado que escribe el capturador (``None`` si no existe o está a medias)."""
    try:
        with open(ruta, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def captura_activa(estado: dict | None, ahora: datetime | None = None, tolerancia_segundos: float = 5) -> bool:
    """La captura está activa si el capturador lo dice y actualizó el estado hace poco.

    Si el proceso se cerró de golpe, ``activo`` queda en true pero la fecha deja
    de avanzar; por eso también se mira la antigüedad.
    """
    if not estado or not estado.get("activo") or not estado.get("actualizado"):
        return False
    try:
        actualizado = datetime.fromisoformat(estado["actualizado"])
    except (TypeError, ValueError):
        return False
    ahora = ahora or datetime.now()
    return (ahora - actualizado).total_seconds() <= tolerancia_segundos


def flujos_en_vivo(historial: pd.DataFrame | None) -> pd.DataFrame:
    """Solo las filas del historial que vienen de la captura real (no de la demo con CSV)."""
    if historial is None or "archivo_origen" not in historial.columns:
        return pd.DataFrame(columns=COLUMNAS_VIVO)
    vivo = historial[historial["archivo_origen"].astype(str) == ORIGEN_CAPTURA].copy()
    for columna in COLUMNAS_VIVO:
        if columna not in vivo.columns:
            vivo[columna] = None
    return vivo.reset_index(drop=True)


def resumen_por_ip_origen(vivo: pd.DataFrame) -> pd.DataFrame:
    """Flujos y anómalos por IP de origen, para ver de un vistazo quién genera qué."""
    if vivo.empty:
        return pd.DataFrame(columns=["IP origen", "Flujos", "Anómalos", "Proporción anómala"])
    resultado = vivo["resultado"].astype(str)
    tabla = (vivo.assign(anomalo=(resultado == "ANOMALO").astype(int))
             .groupby(vivo["ip_origen"].fillna("(desconocida)").astype(str))
             .agg(Flujos=("anomalo", "size"), Anómalos=("anomalo", "sum")))
    tabla["Proporción anómala"] = tabla["Anómalos"] / tabla["Flujos"]
    tabla = tabla.sort_values(["Flujos", "Anómalos"], ascending=False).reset_index()
    return tabla.rename(columns={"ip_origen": "IP origen"})


def umbral_en_vivo(vivo: pd.DataFrame, por_defecto: float | None) -> float | None:
    """Umbral del modelo con el que se evaluó el flujo más reciente (base o laboratorio)."""
    if vivo is not None and "umbral" in vivo.columns:
        valores = pd.to_numeric(vivo["umbral"], errors="coerce").dropna()
        if not valores.empty:
            return float(valores.iloc[-1])
    return por_defecto


# ---------------------------------------------------------------------------
# Modelo de laboratorio (reportes/laboratorio/)
# ---------------------------------------------------------------------------
def tabla_metricas_laboratorio(metricas: pd.DataFrame) -> pd.DataFrame:
    """metricas.csv del laboratorio (una fila por modelo) con nombres legibles."""
    columnas = {"modelo": "Modelo", "precision": "Precision", "recall": "Recall", "f1": "F1",
                "fpr": "FPR", "roc_auc": "ROC-AUC", "umbral": "Umbral", "total_flujos": "Flujos evaluados"}
    tabla = metricas[[c for c in columnas if c in metricas.columns]].rename(columns=columnas)
    return tabla.round(4)


def tabla_por_tipo_laboratorio(por_tipo: pd.DataFrame) -> pd.DataFrame:
    """Una fila por tipo (normal, escaneo, ráfaga) y una columna por modelo."""
    tabla = por_tipo.pivot_table(index="Label", columns="modelo", values="proporcion_detectada").reset_index()
    flujos = por_tipo.groupby("Label")["flujos"].first().rename("Flujos").reset_index()
    tabla = flujos.merge(tabla, on="Label").rename(columns={"Label": "Tipo"})
    tabla.columns.name = None
    return tabla.sort_values("Flujos", ascending=False).reset_index(drop=True)


# ---------------------------------------------------------------------------
# Clasificación de ataques (incidentes.csv y reportes/clasificador/)
# ---------------------------------------------------------------------------
GRUPOS_INCIDENTE = [("escaneo_puertos", "Escaneos de puertos"), ("rafaga_conexiones", "Ráfagas (DoS)"),
                    ("transferencia_masiva", "Transferencias masivas"), ("otros", "Otras anomalías")]


def ultimos_incidentes(incidentes: pd.DataFrame | None) -> pd.DataFrame:
    """Última actualización de cada incidente, el más reciente primero."""
    if incidentes is None or incidentes.empty or "id_incidente" not in incidentes.columns:
        return pd.DataFrame()
    ultimos = incidentes.drop_duplicates("id_incidente", keep="last")
    return ultimos.sort_values("ultimo", ascending=False).reset_index(drop=True)


def conteo_incidentes(ultimos: pd.DataFrame) -> dict:
    """Incidentes por grupo (escaneo, ráfaga, transferencia, otros)."""
    conteo = {clave: 0 for clave, _ in GRUPOS_INCIDENTE}
    if ultimos.empty:
        return conteo
    for tipo in ultimos["tipo_ataque"].astype(str):
        conteo[tipo if tipo in conteo else "otros"] += 1
    return conteo


def tabla_incidentes(ultimos: pd.DataFrame) -> pd.DataFrame:
    """Incidentes con nombres legibles para el panel."""
    from src.clasificacion.reglas import nombre_tipo

    if ultimos.empty:
        return pd.DataFrame()
    tabla = pd.DataFrame({
        "Tipo de ataque": ultimos["tipo_ataque"].astype(str).map(nombre_tipo),
        "Atacante": ultimos["ip_atacante"],
        "Víctima": ultimos["ip_victima"],
        "Inicio": ultimos["inicio"].astype(str).str[11:19],
        "Duración (s)": ultimos["duracion_segundos"],
        "Flujos": ultimos["flujos"],
        "Puertos": ultimos["puertos_distintos"],
        "Conexiones/s": ultimos["conexiones_por_segundo"],
        "Detectado por": ultimos["detectado_por"],
        "Detalle": ultimos["detalle"],
    })
    return tabla


def leer_resultados_clasificador(config: dict) -> dict:
    """Métricas, reporte por familia, matriz y aplicación a la sesión real (lo que exista)."""
    carpeta = Path(config["rutas"]["reportes_clasificador"])
    salida: dict = {"carpeta": carpeta}
    try:
        with open(carpeta / "metricas_clasificador.json", encoding="utf-8") as f:
            salida["metricas"] = json.load(f)
    except (OSError, json.JSONDecodeError):
        return salida
    salida["reporte"], _ = leer_csv(carpeta / "reporte_clasificacion.csv")
    salida["sesion"], _ = leer_csv(carpeta / "sesion_laboratorio.csv")
    matriz = carpeta / "matriz_confusion.png"
    salida["matriz"] = matriz if matriz.exists() else None
    return salida
