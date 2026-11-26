"""Análisis de una sesión de captura en vivo (flujos de PC2 hacia PC1).

Clasifica cada flujo por **su forma de tráfico**, no por la hora: así el análisis no
depende de que los relojes de PC1 y PC2 estén sincronizados y no confunde el tráfico
normal que ocurre durante un episodio anómalo con el propio episodio.

* ``ping``: ICMP.
* ``descarga grande``: al puerto HTTP con >= 20 KB de respuesta (grande.bin, 256 KB;
  algunas llegan incompletas porque Npcap pierde paquetes con mucho volumen).
* ``descarga pequeña``: al puerto HTTP con menos de 20 KB (prueba.txt + cabeceras, ~200 B).
* ``ráfaga``: al puerto de las ráfagas.
* ``otro``: el resto (NetBIOS, SSDP, la verificación HEAD, etc.).

Si además se da el CSV de escenarios de PC2, cada flujo recibe el tramo en el que
empezó (``mixto_normal`` / ``mixto_anomalo`` ...) para el resumen por tramo.
"""

from __future__ import annotations

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

UMBRAL_DESCARGA_GRANDE_BYTES = 20_000
ORDEN_TIPOS = ["descarga pequeña", "ping", "otro", "descarga grande", "ráfaga"]
# Tipos que el escenario de PC2 genera como anómalos (lo esperado es que se marquen).
TIPOS_ANOMALOS = {"descarga grande", "ráfaga"}

# Misma paleta que el panel (datos_panel.py).
COLORES = {"descarga pequeña": "#2a78d6", "ping": "#52514e", "otro": "#9b9a96",
           "descarga grande": "#d03b3b", "ráfaga": "#eda100"}
COLOR_TINTA, COLOR_REJILLA, COLOR_FONDO = "#52514e", "#e4e3df", "#fcfcfb"
COLOR_TRAMO_ANOMALO = "#f6d6d6"


def cargar_sesion(ruta_flujos, ip_pc2: str, desde=None, hasta=None) -> pd.DataFrame:
    """Flujos capturados en los que participa PC2, opcionalmente entre ``desde`` y ``hasta``."""
    df = pd.read_csv(ruta_flujos, encoding="utf-8")
    df["inicio"] = pd.to_datetime(df["inicio_flujo"], format="ISO8601")
    df = df[(df["ip_origen"].astype(str) == ip_pc2) | (df["ip_destino"].astype(str) == ip_pc2)]
    if desde is not None:
        df = df[df["inicio"] >= pd.Timestamp(desde)]
    if hasta is not None:
        df = df[df["inicio"] <= pd.Timestamp(hasta)]
    return df.sort_values("inicio").reset_index(drop=True)


def clasificar_trafico(df: pd.DataFrame, puerto_http: int = 8000, puerto_rafaga: int = 8080) -> pd.Series:
    """Tipo de tráfico de cada flujo.

    Si la captura perdió el primer paquete de PC2 (el SYN), el flujo empieza con un
    paquete de PC1 y queda "al revés": el puerto del servidor aparece como puerto de
    origen y los bytes descargados como bytes "forward". Se reconocen ambos sentidos.
    """
    destino = pd.to_numeric(df["Destination Port"], errors="coerce")
    origen = pd.to_numeric(df.get("puerto_origen"), errors="coerce") if "puerto_origen" in df else destino * 0
    tcp = df["protocolo"].astype(str) == "TCP"
    al_reves = tcp & destino.isin([puerto_http, puerto_rafaga]).eq(False) & origen.isin([puerto_http, puerto_rafaga])
    puerto = destino.where(~al_reves, origen)
    bytes_servidor = pd.to_numeric(df["Total Length of Bwd Packets"], errors="coerce").fillna(0).where(
        ~al_reves, pd.to_numeric(df["Total Length of Fwd Packets"], errors="coerce").fillna(0))
    tipo = pd.Series("otro", index=df.index, dtype=object)
    tipo[(puerto == puerto_http) & (bytes_servidor < UMBRAL_DESCARGA_GRANDE_BYTES)] = "descarga pequeña"
    tipo[(puerto == puerto_http) & (bytes_servidor >= UMBRAL_DESCARGA_GRANDE_BYTES)] = "descarga grande"
    tipo[puerto == puerto_rafaga] = "ráfaga"
    tipo[df["protocolo"].astype(str) == "ICMP"] = "ping"
    return tipo


def asignar_tramos(df: pd.DataFrame, escenarios: pd.DataFrame | None) -> pd.Series:
    """Tipo de escenario de PC2 en el que empezó cada flujo ('' si ninguno)."""
    tramo = pd.Series("", index=df.index, dtype=object)
    if escenarios is None or escenarios.empty:
        return tramo
    ini = pd.to_datetime(escenarios["fecha_hora_inicio"], format="ISO8601")
    fin = pd.to_datetime(escenarios["fecha_hora_fin"], format="ISO8601")
    for i, f, t in zip(ini, fin, escenarios["tipo_escenario"].astype(str)):
        tramo[(df["inicio"] >= i) & (df["inicio"] <= f) & (tramo == "")] = t
    return tramo


def resumir(df: pd.DataFrame, columna: str) -> pd.DataFrame:
    """Flujos, anómalos, proporción y puntajes por valor de ``columna``."""
    if df.empty:
        return pd.DataFrame(columns=[columna, "flujos", "anomalos", "no_evaluables", "proporcion_anomala",
                                     "score_medio", "score_minimo"])
    score = pd.to_numeric(df["score"], errors="coerce")
    tabla = (df.assign(anomalo=(df["resultado"] == "ANOMALO").astype(int),
                       no_eval=(df["resultado"] == "NO_EVALUABLE").astype(int), score_num=score)
             .groupby(columna)
             .agg(flujos=("anomalo", "size"), anomalos=("anomalo", "sum"), no_evaluables=("no_eval", "sum"),
                  score_medio=("score_num", "mean"), score_minimo=("score_num", "min"))
             .reset_index())
    tabla["proporcion_anomala"] = tabla["anomalos"] / tabla["flujos"]
    if columna == "tipo_trafico":
        tabla["_orden"] = tabla[columna].map({t: i for i, t in enumerate(ORDEN_TIPOS)})
        tabla = tabla.sort_values("_orden").drop(columns="_orden")
    return tabla[[columna, "flujos", "anomalos", "no_evaluables", "proporcion_anomala",
                  "score_medio", "score_minimo"]].reset_index(drop=True)


def metricas_globales(df: pd.DataFrame) -> dict:
    """Matriz de confusión tomando como 'esperado anómalo' los tipos que PC2 genera como ataque."""
    evaluables = df[df["resultado"] != "NO_EVALUABLE"]
    esperado = evaluables["tipo_trafico"].isin(TIPOS_ANOMALOS)
    marcado = evaluables["resultado"] == "ANOMALO"
    vp, fp = int((esperado & marcado).sum()), int((~esperado & marcado).sum())
    fn, vn = int((esperado & ~marcado).sum()), int((~esperado & ~marcado).sum())
    solo_descargas = evaluables["tipo_trafico"].isin({"descarga grande", "descarga pequeña"})
    ve = evaluables[solo_descargas]
    return {
        "flujos": int(len(df)), "evaluables": int(len(evaluables)),
        "verdaderos_positivos": vp, "falsos_positivos": fp, "falsos_negativos": fn, "verdaderos_negativos": vn,
        "precision": vp / (vp + fp) if vp + fp else 0.0,
        "recall": vp / (vp + fn) if vp + fn else 0.0,
        "fpr": fp / (fp + vn) if fp + vn else 0.0,
        # Solo descargas (grandes = ataque, pequeñas = normal): lo que el modelo sí distingue.
        "recall_descargas_grandes": float((ve[ve["tipo_trafico"] == "descarga grande"]["resultado"] == "ANOMALO").mean())
        if (ve["tipo_trafico"] == "descarga grande").any() else float("nan"),
        "fpr_descargas_pequenas": float((ve[ve["tipo_trafico"] == "descarga pequeña"]["resultado"] == "ANOMALO").mean())
        if (ve["tipo_trafico"] == "descarga pequeña").any() else float("nan"),
    }


def figura_sesion(df: pd.DataFrame, umbral: float, escenarios: pd.DataFrame | None = None):
    """Puntaje de cada flujo en el tiempo, por tipo de tráfico, con el umbral y los tramos anómalos."""
    fig, ax = plt.subplots(figsize=(12, 4.5))
    fig.patch.set_facecolor(COLOR_FONDO)
    ax.set_facecolor(COLOR_FONDO)
    if escenarios is not None and not escenarios.empty:
        anom = escenarios[escenarios["tipo_escenario"].astype(str).str.contains("anomalo|rafaga|escaneo")]
        for i, f in zip(pd.to_datetime(anom["fecha_hora_inicio"], format="ISO8601"),
                        pd.to_datetime(anom["fecha_hora_fin"], format="ISO8601")):
            ax.axvspan(i, f, color=COLOR_TRAMO_ANOMALO, zorder=0, lw=0)
    score = pd.to_numeric(df["score"], errors="coerce")
    for tipo in ORDEN_TIPOS:
        sel = (df["tipo_trafico"] == tipo) & score.notna()
        if not sel.any():
            continue
        marcados = sel & (df["resultado"] == "ANOMALO")
        ax.scatter(df.loc[sel & ~marcados, "inicio"], score[sel & ~marcados], s=10, color=COLORES[tipo],
                   alpha=0.6, zorder=3, label=f"{tipo} ({int(sel.sum())})")
        if marcados.any():
            ax.scatter(df.loc[marcados, "inicio"], score[marcados], s=34, marker="X", color=COLORES[tipo],
                       edgecolors=COLOR_FONDO, linewidths=0.6, zorder=4)
    ax.axhline(umbral, color=COLOR_TINTA, linestyle="--", linewidth=1.3, zorder=2)
    ax.annotate(f"Umbral {umbral:.4f} (X = marcado anómalo)", xy=(0, umbral), xycoords=("axes fraction", "data"),
                xytext=(4, 4), textcoords="offset points", fontsize=9, color=COLOR_TINTA)
    ax.set_xlabel("Hora de inicio del flujo (reloj de PC1)", color=COLOR_TINTA)
    ax.set_ylabel("score (más bajo = más anómalo)", color=COLOR_TINTA)
    ax.grid(axis="y", color=COLOR_REJILLA, linewidth=0.8)
    for lado in ("top", "right"):
        ax.spines[lado].set_visible(False)
    ax.tick_params(colors=COLOR_TINTA, labelsize=9)
    ax.legend(loc="lower left", fontsize=8, frameon=False, ncol=5, bbox_to_anchor=(0, 1.0))
    fig.autofmt_xdate()
    fig.tight_layout()
    return fig


def metricas_combinadas(df: pd.DataFrame) -> dict:
    """Detección por flujo del sistema completo: modelo (ANOMALO) **o** una regla por ventana.

    Esperado anómalo = los tipos que PC2 genera como ataque (descargas grandes y ráfaga).
    """
    from src.clasificacion.reglas import ESCANEO, RAFAGA, TRANSFERENCIA

    esperado = df["tipo_trafico"].isin(TIPOS_ANOMALOS)
    reglas = df.get("tipo_ataque", pd.Series("", index=df.index)).isin([ESCANEO, RAFAGA, TRANSFERENCIA])
    marcado = (df["resultado"] == "ANOMALO") | reglas
    vp, fp = int((esperado & marcado).sum()), int((~esperado & marcado).sum())
    fn, vn = int((esperado & ~marcado).sum()), int((~esperado & ~marcado).sum())
    return {
        "verdaderos_positivos": vp, "falsos_positivos": fp, "falsos_negativos": fn, "verdaderos_negativos": vn,
        "precision": vp / (vp + fp) if vp + fp else 0.0,
        "recall": vp / (vp + fn) if vp + fn else 0.0,
        "fpr": fp / (fp + vn) if fp + vn else 0.0,
    }


def cruce_trafico_ataque(df: pd.DataFrame) -> pd.DataFrame:
    """Flujos por tipo de tráfico (filas) y tipo de ataque asignado (columnas)."""
    tipo = df["tipo_ataque"].replace("", "(ninguno)").fillna("(ninguno)")
    tabla = pd.crosstab(df["tipo_trafico"], tipo)
    orden = [t for t in ORDEN_TIPOS if t in tabla.index]
    return tabla.loc[orden].reset_index()
