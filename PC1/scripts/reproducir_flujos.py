"""Simulador de monitoreo en vivo: reproduce flujos de CSV ya existentes.

Sirve para demostrar el ciclo captura → modelo → alerta antes de tener la captura
real con CICFlowMeter. Toma una muestra pequeña de uno o varios CSV, la mezcla y
la procesa fila por fila con una pausa entre flujos, igual que si llegaran en vivo.

Ejemplos (desde PC1/):
    python scripts/reproducir_flujos.py
    python scripts/reproducir_flujos.py --origen ../Datasets/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv --filas 50
    python scripts/reproducir_flujos.py --filas 10 --intervalo-segundos 0 --limpiar-alertas
    python scripts/reproducir_flujos.py --origen Wednesday-workingHours.pcap_ISCX.csv --etiqueta Heartbleed

Además de las alertas, cada flujo evaluado se guarda en el historial completo
(``rutas.flujos_analizados``) salvo que se use ``--sin-historial-completo``.
"""

from __future__ import annotations

import argparse
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.alertas.gestor_alertas import procesar_resultado, registrar_flujo_analizado  # noqa: E402
from src.modelo.detector import (  # noqa: E402
    ANOMALO,
    NO_EVALUABLE,
    cargar_detector,
    evaluar_flujo,
    preparar_flujo_para_prediccion,
)
from src.procesamiento.dataset import cargar_configuracion, limpiar_nombres_columnas  # noqa: E402


def leer_argumentos(config: dict) -> argparse.Namespace:
    demo = config["demo"]
    p = argparse.ArgumentParser(description="Reproduce flujos de CSV para simular monitoreo en vivo.")
    p.add_argument("--origen", nargs="+", default=demo["archivos_origen"],
                   help="Uno o más CSV de flujos. Puede ser una ruta o un nombre dentro de la carpeta de datos crudos.")
    p.add_argument("--filas", type=int, default=demo["filas_por_archivo"],
                   help="Cantidad de flujos a tomar de cada archivo de origen.")
    p.add_argument("--intervalo-segundos", type=float, default=demo["intervalo_segundos"],
                   help="Pausa entre flujos para imitar la llegada en vivo.")
    p.add_argument("--semilla", type=int, default=demo["semilla"],
                   help="Semilla del muestreo y la mezcla (para que la demo sea reproducible).")
    p.add_argument("--primeras", action="store_true",
                   help="Tomar las primeras N filas de cada archivo en vez de una muestra aleatoria.")
    p.add_argument("--limpiar-alertas", action="store_true",
                   help="Borrar el CSV de alertas antes de empezar.")
    p.add_argument("--sin-historial-completo", action="store_true",
                   help="No escribir el historial de todos los flujos analizados (solo alertas).")
    p.add_argument("--etiqueta", default=None,
                   help="Tomar solo flujos con este valor de Label (p. ej. Heartbleed). Solo elige "
                        "qué filas se reproducen; el modelo nunca recibe la etiqueta.")
    return p.parse_args()


def resolver_origen(config: dict, origen: str) -> Path:
    """Acepta una ruta (relativa al directorio actual o absoluta) o un nombre de archivo de Datasets."""
    ruta = Path(origen)
    if ruta.exists():
        return ruta
    alternativa = config["rutas"]["datos_crudos"] / origen
    if alternativa.exists():
        return alternativa
    raise FileNotFoundError(f"No se encontró el archivo de origen: {origen}")


def cargar_muestra(
    config: dict,
    ruta: Path,
    filas: int,
    semilla: int,
    primeras: bool,
    filtro_etiqueta: str | None = None,
) -> pd.DataFrame:
    """Lee solo las columnas necesarias y devuelve una muestra de ``filas`` flujos.

    Con ``filtro_etiqueta`` solo se consideran las filas con ese ``Label``.
    """
    etiqueta = config["datos"]["columna_etiqueta"]
    necesarias = set(config["caracteristicas"]) | {etiqueta}
    lectura = dict(usecols=lambda c: c.strip() in necesarias, encoding=config["datos"]["codificacion"])
    if primeras and not filtro_etiqueta:
        df = limpiar_nombres_columnas(pd.read_csv(ruta, nrows=filas, **lectura))
    else:
        df = limpiar_nombres_columnas(pd.read_csv(ruta, **lectura))
        if filtro_etiqueta:
            df = df[df[etiqueta].astype(str).str.strip() == filtro_etiqueta.strip()]
        if primeras:
            df = df.head(filas)
        else:
            df = df.sample(n=min(filas, len(df)), random_state=semilla)

    # Identificación: el dataset no trae IPs. id_flujo = archivo + índice de la fila en el CSV.
    df["id_flujo"] = [f"{ruta.stem}#{i}" for i in df.index]
    df["archivo_origen"] = ruta.name
    df["ip_origen"] = None
    df["ip_destino"] = None
    df["puerto_origen"] = None
    df["puerto_destino"] = df["Destination Port"]  # sí existe en el dataset; solo se usa para mostrar
    if etiqueta in df.columns:
        df["etiqueta_real"] = df[etiqueta].astype(str).str.strip()
    return df


def main() -> None:
    config = cargar_configuracion()
    args = leer_argumentos(config)
    ruta_alertas = config["rutas"]["alertas"]
    ruta_historial = None if args.sin_historial_completo else config["rutas"]["flujos_analizados"]

    if args.limpiar_alertas and ruta_alertas.exists():
        ruta_alertas.unlink()

    detector = cargar_detector(config)
    print(f"Detector cargado | umbral = {detector['umbral']:.6f}")

    partes = []
    for origen in args.origen:
        ruta = resolver_origen(config, origen)
        muestra = cargar_muestra(config, ruta, args.filas, args.semilla, args.primeras, args.etiqueta)
        filtro = f" (Label = {args.etiqueta})" if args.etiqueta else ""
        print(f"Origen: {ruta.name}{filtro} → {len(muestra)} flujos")
        partes.append(muestra)
    flujos = pd.concat(partes, ignore_index=True).sample(frac=1, random_state=args.semilla)
    if flujos.empty:
        print("\nNo hay flujos para reproducir con esos parámetros "
              "(¿la etiqueta existe en ese archivo?).")
        sys.exit(2)

    print(f"\nReproduciendo {len(flujos)} flujos (intervalo {args.intervalo_segundos}s)...\n")
    conteo = Counter()
    for _, fila in flujos.iterrows():
        preparado = preparar_flujo_para_prediccion(fila, detector["orden_columnas"])
        res = evaluar_flujo(detector, preparado)
        conteo[res["resultado"]] += 1

        evaluado = {
            # Misma fecha para la alerta y el historial; milisegundos para conservar el orden.
            "fecha_hora": datetime.now().isoformat(timespec="milliseconds"),
            "id_flujo": fila["id_flujo"],
            "archivo_origen": fila["archivo_origen"],
            "ip_origen": fila["ip_origen"],
            "ip_destino": fila["ip_destino"],
            "puerto_origen": fila["puerto_origen"],
            "puerto_destino": fila["puerto_destino"],
            **res,
        }
        procesar_resultado(ruta_alertas, evaluado)
        if ruta_historial is not None:
            registrar_flujo_analizado(ruta_historial, evaluado)

        # La etiqueta real solo se muestra para la demo; el modelo nunca la recibe.
        real = f"(Label real: {fila.get('etiqueta_real', '?')})"
        if res["resultado"] == NO_EVALUABLE:
            print(f"[NO_EVALUABLE] {fila['id_flujo']} {real}")
        else:
            marca = "[ANOMALO]" if res["resultado"] == ANOMALO else "[NORMAL] "
            print(f"{marca} score={res['score']:+.4f}  {fila['id_flujo']}  "
                  f"puerto_destino={fila['puerto_destino']}  {real}")
        if args.intervalo_segundos > 0:
            time.sleep(args.intervalo_segundos)

    print("\n=== Resumen ===")
    print(f"  Flujos procesados: {sum(conteo.values())}")
    print(f"  Normales:          {conteo['NORMAL']}")
    print(f"  Anómalos:          {conteo['ANOMALO']}")
    print(f"  No evaluables:     {conteo['NO_EVALUABLE']}")
    print(f"  CSV de alertas:    {ruta_alertas}")
    print(f"  Historial completo: {ruta_historial or 'desactivado (--sin-historial-completo)'}")


if __name__ == "__main__":
    main()
