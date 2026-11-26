"""Guarda y analiza una sesión de captura en vivo (tráfico de PC2) en reportes/sesiones/<nombre>/.

Guarda: los flujos de la sesión (con su tipo de tráfico), las tablas de resultados,
la gráfica de puntajes en el tiempo y un RESUMEN.md listo para la presentación.
Esa carpeta NO está ignorada por git: los resultados quedan versionados.

Ejemplos (desde PC1/):
    python scripts/analizar_sesion.py --desde "2026-11-25 16:40" --nombre presentacion
    python scripts/analizar_sesion.py --escenarios-pc2 datos/laboratorio/escenarios_pc2.csv
    python scripts/analizar_sesion.py --ip-pc2 192.168.1.20 --desde "2026-11-26 10:00" --hasta "2026-11-26 10:30"

Para el resumen por tramo, copiar antes PC2/registros/escenarios_ejecutados.csv a PC1.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import datetime
from pathlib import Path

import matplotlib.pyplot as plt

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.analisis.sesion import (  # noqa: E402
    asignar_tramos,
    cargar_sesion,
    clasificar_trafico,
    cruce_trafico_ataque,
    figura_sesion,
    metricas_combinadas,
    metricas_globales,
    resumir,
)
from src.clasificacion.reglas import clasificar_dataframe, nombre_tipo  # noqa: E402
from src.modelo.laboratorio import cargar_escenarios_pc2  # noqa: E402
from src.procesamiento.dataset import cargar_configuracion  # noqa: E402


def tabla_md(df, formatos: dict) -> str:
    cab = "| " + " | ".join(df.columns) + " |\n|" + "---|" * len(df.columns) + "\n"
    filas = []
    for _, fila in df.iterrows():
        filas.append("| " + " | ".join(formatos.get(c, str)(fila[c]) for c in df.columns) + " |")
    return cab + "\n".join(filas)


def main() -> None:
    config = cargar_configuracion()
    p = argparse.ArgumentParser(description="Guarda y analiza una sesión de captura en vivo.")
    p.add_argument("--flujos", default=str(config["rutas"]["flujos_capturados"]))
    p.add_argument("--escenarios-pc2", default=None, help="CSV de escenarios copiado desde PC2 (opcional).")
    p.add_argument("--ip-pc2", default=(config.get("captura") or {}).get("ip_pc2"))
    p.add_argument("--desde", default=None, help='Inicio de la sesión, ej. "2026-11-25 16:40".')
    p.add_argument("--hasta", default=None)
    p.add_argument("--puerto-http", type=int, default=8000)
    p.add_argument("--puerto-rafaga", type=int, default=8080)
    p.add_argument("--nombre", default=None, help="Nombre de la carpeta (por defecto, fecha y hora de inicio).")
    args = p.parse_args()

    df = cargar_sesion(args.flujos, args.ip_pc2, args.desde, args.hasta)
    if df.empty:
        sys.exit(f"No hay flujos de {args.ip_pc2} en {args.flujos} para ese intervalo.")
    escenarios = cargar_escenarios_pc2(args.escenarios_pc2) if args.escenarios_pc2 else None
    if escenarios is not None:
        escenarios = escenarios[(escenarios["fecha_hora_fin"] >= df["inicio"].min())
                                & (escenarios["fecha_hora_inicio"] <= df["inicio"].max())]
    df["tipo_trafico"] = clasificar_trafico(df, args.puerto_http, args.puerto_rafaga)
    df["tramo_pc2"] = asignar_tramos(df, escenarios)
    # Reglas por ventana sobre la sesión (mismo código que en vivo).
    clasificados, incidentes = clasificar_dataframe(df, config.get("clasificacion"))
    df["tipo_ataque"], df["id_incidente"] = clasificados["tipo_ataque"], clasificados["id_incidente"]

    nombre = args.nombre or df["inicio"].min().strftime("%Y-%m-%d_%H%M")
    carpeta = config["rutas"]["reportes"] / "sesiones" / nombre
    carpeta.mkdir(parents=True, exist_ok=True)
    umbral = float(df["umbral"].dropna().iloc[-1])

    por_tipo = resumir(df, "tipo_trafico")
    metricas = metricas_globales(df)
    combinadas = metricas_combinadas(df)
    cruce = cruce_trafico_ataque(df)
    df.drop(columns=["inicio"]).to_csv(carpeta / "flujos.csv", index=False)
    por_tipo.to_csv(carpeta / "resumen_por_tipo.csv", index=False)
    incidentes.to_csv(carpeta / "incidentes.csv", index=False)
    cruce.to_csv(carpeta / "clasificacion_por_tipo.csv", index=False)
    por_tramo = None
    if escenarios is not None and not escenarios.empty:
        shutil.copy(args.escenarios_pc2, carpeta / "escenarios_pc2.csv")
        por_tramo = resumir(df[df["tramo_pc2"] != ""], "tramo_pc2")
        por_tramo.to_csv(carpeta / "resumen_por_tramo.csv", index=False)
    with open(carpeta / "metricas.json", "w", encoding="utf-8") as f:
        json.dump({"umbral": umbral, "ip_pc2": args.ip_pc2, **metricas,
                   "con_reglas": combinadas, "incidentes": int(len(incidentes))}, f, ensure_ascii=False, indent=2)
    fig = figura_sesion(df, umbral, escenarios)
    fig.savefig(carpeta / "puntajes.png", dpi=130)
    plt.close(fig)

    pct = lambda v: "—" if v != v else f"{v:.1%}"  # noqa: E731
    num = lambda v: f"{int(v):,}"  # noqa: E731
    sc = lambda v: "—" if v != v else f"{v:+.4f}"  # noqa: E731
    fmt = {"flujos": num, "anomalos": num, "no_evaluables": num, "proporcion_anomala": pct,
           "score_medio": sc, "score_minimo": sc}
    modelo = "laboratorio" if abs(umbral - (-0.15735438614690697)) > 1e-9 else "base (CICIDS2017)"
    texto = f"""# Sesión {nombre}

Generado el {datetime.now():%Y-%m-%d %H:%M} por `scripts/analizar_sesion.py`.

- Flujos de PC2 ({args.ip_pc2}) capturados en PC1: **{metricas['flujos']:,}**, del
  {df['inicio'].min():%Y-%m-%d %H:%M:%S} al {df['inicio'].max():%H:%M:%S} (reloj de PC1).
- Modelo: {modelo}, umbral {umbral:.6f} (anómalo si score < umbral).

## Resultado por tipo de tráfico

Cada flujo se clasifica por su forma (puerto y bytes), no por la hora.

{tabla_md(por_tipo, fmt)}

## Lectura

- **Descargas grandes (ataque simulado):** {pct(metricas['recall_descargas_grandes'])} marcadas como anómalas.
- **Descargas pequeñas (tráfico normal):** {pct(metricas['fpr_descargas_pequenas'])} marcadas (falsos positivos).
- **Ráfaga:** cada conexión por separado es una conexión TCP corta y normal; Isolation Forest
  puntúa flujo a flujo y no ve que llegan cientos por segundo desde la misma IP. Es la
  limitación conocida del modelo (también 0 % en PortScan/DoS de CICIDS2017).
- Tomando como ataque descargas grandes + ráfaga: precision {pct(metricas['precision'])},
  recall {pct(metricas['recall'])}, FPR {pct(metricas['fpr'])}
  (VP {metricas['verdaderos_positivos']:,}, FP {metricas['falsos_positivos']:,},
  FN {metricas['falsos_negativos']:,}, VN {metricas['verdaderos_negativos']:,}).
"""
    tabla_incidentes = "(ninguno)"
    if len(incidentes):
        vista = incidentes.assign(tipo_ataque=incidentes["tipo_ataque"].map(nombre_tipo),
                                  inicio=incidentes["inicio"].str[11:19])
        tabla_incidentes = tabla_md(vista[["tipo_ataque", "ip_atacante", "inicio", "duracion_segundos",
                                           "flujos", "detectado_por", "detalle"]], {})
    minimo_rafaga = (config.get("clasificacion") or {}).get("min_conexiones_rafaga", 50)
    texto += f"""
## Clasificación de ataques (reglas por ventana)

Las reglas miran juntos los flujos de cada IP en los últimos segundos (ver
`src/clasificacion/reglas.py`). Flujos por tipo de tráfico y tipo de ataque asignado:

{tabla_md(cruce, {})}

Incidentes detectados: **{len(incidentes)}**

{tabla_incidentes}

Sistema completo (modelo **o** reglas), con descargas grandes + ráfaga como ataque:
precision {pct(combinadas['precision'])}, recall {pct(combinadas['recall'])}, FPR {pct(combinadas['fpr'])}
(VP {combinadas['verdaderos_positivos']:,}, FP {combinadas['falsos_positivos']:,},
FN {combinadas['falsos_negativos']:,}, VN {combinadas['verdaderos_negativos']:,}).
Las primeras conexiones de cada ráfaga no se marcan: la regla necesita acumular
{minimo_rafaga} en la ventana.
"""
    if por_tramo is not None:
        texto += f"""
## Resultado por tramo de PC2

Según el registro de escenarios de PC2 (`escenarios_pc2.csv`). El tráfico normal que
ocurre durante un episodio anómalo cuenta dentro de ese episodio.

{tabla_md(por_tramo, fmt)}
"""
    texto += """
## Gráfica

![Puntaje de cada flujo en el tiempo](puntajes.png)

Cada punto es un flujo; las X son los marcados como anómalos. """ + (
        "Las franjas rojas son los tramos anómalos según PC2." if por_tramo is not None else
        "Sin el CSV de PC2 no se dibujan los tramos.") + """

## Archivos

`flujos.csv` (flujos de la sesión con `tipo_trafico`), `resumen_por_tipo.csv`, """ + (
        "`resumen_por_tramo.csv`, `escenarios_pc2.csv`, " if por_tramo is not None else "") + \
        "`incidentes.csv`, `clasificacion_por_tipo.csv`, `metricas.json` y `puntajes.png`.\n"
    (carpeta / "RESUMEN.md").write_text(texto, encoding="utf-8")

    print(por_tipo.to_string(index=False))
    print(f"\nSesión guardada en {carpeta}")


if __name__ == "__main__":
    main()
