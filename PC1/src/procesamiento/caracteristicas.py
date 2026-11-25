"""Selección y limpieza de las 10 características usadas por el modelo."""

from __future__ import annotations

import numpy as np
import pandas as pd

from src.procesamiento.dataset import ErrorColumnas

# Columnas de volumen y tasa que se transforman con log1p en el experimento.
# Las de conteo o categóricas (paquetes, SYN, puerto) no se tocan.
COLUMNAS_LOG1P = [
    "Flow Duration",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
]


def seleccionar_caracteristicas(
    df: pd.DataFrame,
    caracteristicas: list[str],
    columna_etiqueta: str | None = None,
) -> pd.DataFrame:
    """Devuelve solo las características (en orden fijo) y, opcionalmente, la etiqueta.

    Lanza ``ErrorColumnas`` con un mensaje claro si falta alguna columna.
    """
    columnas = list(caracteristicas) + ([columna_etiqueta] if columna_etiqueta else [])
    faltantes = [c for c in columnas if c not in df.columns]
    if faltantes:
        raise ErrorColumnas(f"Faltan columnas requeridas: {faltantes}")
    return df[columnas].copy()


def limpiar(
    df: pd.DataFrame,
    caracteristicas: list[str],
    columna_etiqueta: str | None = None,
    verbose: bool = True,
    aplicar_log1p: bool = False,
) -> pd.DataFrame:
    """Limpieza completa de un DataFrame de flujos.

    Pasos:
      1. Seleccionar las 10 características (+ etiqueta) en orden fijo.
      2. Convertir a numérico (lo no convertible pasa a NaN).
      3. Reemplazar +/-infinito por NaN.
      4. Eliminar filas con NaN en las características.
      5. Eliminar duplicados exactos considerando SOLO las características.
      6. Solo si ``aplicar_log1p=True`` (experimento; por defecto no se hace):
         eliminar las filas con negativos en ``COLUMNAS_LOG1P`` y aplicar
         ``np.log1p`` a esas columnas. Va después de los duplicados para no
         cambiar qué cuenta como duplicado.

    Imprime cuántas filas quedan tras cada paso. Con log1p, el número de filas
    eliminadas por negativos queda en ``resultado.attrs["filas_negativas_eliminadas"]``.
    """
    caracteristicas = list(caracteristicas)

    def informar(paso: str, datos: pd.DataFrame) -> None:
        if verbose:
            print(f"  [limpieza] {paso:<35} {len(datos):>12,} filas")

    informar("inicial", df)
    datos = seleccionar_caracteristicas(df, caracteristicas, columna_etiqueta)

    for col in caracteristicas:
        datos[col] = pd.to_numeric(datos[col], errors="coerce").astype("float64")
    informar("conversión a numérico", datos)

    n_inf = int(np.isinf(datos[caracteristicas].to_numpy()).any(axis=1).sum())
    datos[caracteristicas] = datos[caracteristicas].replace([np.inf, -np.inf], np.nan)
    if verbose:
        print(f"  [limpieza] filas con infinitos convertidos a NaN: {n_inf:,}")

    datos = datos.dropna(subset=caracteristicas)
    informar("tras eliminar NaN/infinitos", datos)

    datos = datos.drop_duplicates(subset=caracteristicas, keep="first")
    informar("tras eliminar duplicados", datos)

    if not aplicar_log1p:
        return datos.reset_index(drop=True)

    columnas_log = [c for c in COLUMNAS_LOG1P if c in caracteristicas]
    # log1p de un valor < 0 no es válido (da NaN, o -inf en -1). CICIDS2017 trae
    # negativos por errores de cálculo: se tratan como inválidos y se eliminan.
    negativos = (datos[columnas_log] < 0).any(axis=1)
    n_negativos = int(negativos.sum())
    if verbose:
        por_columna = (datos[columnas_log] < 0).sum()
        detalle = ", ".join(f"{c}={n:,}" for c, n in por_columna.items() if n)
        print(f"  [limpieza] filas con negativos (antes de log1p): {n_negativos:,}"
              + (f" [{detalle}]" if detalle else ""))
    datos = datos[~negativos].copy()
    informar("tras eliminar negativos", datos)

    datos[columnas_log] = np.log1p(datos[columnas_log])
    if verbose:
        print(f"  [limpieza] log1p aplicado a: {columnas_log}")

    datos = datos.reset_index(drop=True)
    datos.attrs["filas_negativas_eliminadas"] = n_negativos
    return datos
