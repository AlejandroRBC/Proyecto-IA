"""Auditoría: ¿la eliminación de duplicados mezcla etiquetas distintas en la evaluación?

Carga los 7 archivos de evaluación y los limpia de infinitos y NaN, pero sin eliminar
duplicados. Luego agrupa por las 10 características y revisa cuántas etiquetas
distintas hay en cada grupo. Solo diagnostica: no cambia modelos ni métricas.

Uso (desde PC1/):  python scripts/auditoria_duplicados.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.procesamiento.caracteristicas import seleccionar_caracteristicas  # noqa: E402
from src.procesamiento.dataset import cargar_configuracion, cargar_evaluacion  # noqa: E402

ATAQUES_DE_VOLUMEN = ["PortScan", "DDoS", "DoS Hulk"]


def limpiar_sin_deduplicar(df: pd.DataFrame, caracteristicas: list[str], etiqueta: str) -> pd.DataFrame:
    """Mismos pasos que ``limpiar()`` hasta eliminar NaN, sin el paso de duplicados."""
    datos = seleccionar_caracteristicas(df, caracteristicas, etiqueta)
    for col in caracteristicas:
        datos[col] = pd.to_numeric(datos[col], errors="coerce").astype("float64")
    datos[caracteristicas] = datos[caracteristicas].replace([np.inf, -np.inf], np.nan)
    return datos.dropna(subset=caracteristicas).reset_index(drop=True)


def auditar(df: pd.DataFrame, caracteristicas: list[str], etiqueta: str, benigno: str) -> dict:
    """Calcula todos los conteos de la auditoría.

    Devuelve un dict con el resumen, la tabla por etiqueta y las combinaciones conflictivas.
    """
    df = df.copy()
    df["grupo"] = df.groupby(caracteristicas, sort=False).ngroup()
    tam = df.groupby("grupo")["grupo"].transform("size")
    n_etiquetas = df.groupby("grupo")[etiqueta].transform("nunique")
    tiene_benigno = (df[etiqueta] == benigno).groupby(df["grupo"]).transform("any")

    # Lo que hace hoy drop_duplicates(subset=10 características, keep="first").
    eliminada = df.duplicated(subset=caracteristicas, keep="first")
    etiqueta_conservada = df.groupby("grupo")[etiqueta].transform("first")
    # Filas eliminadas cuya etiqueta es distinta a la de la fila que se conserva:
    # esa etiqueta desaparece de la evaluación para ese grupo.
    perdida_de_etiqueta = eliminada & (df[etiqueta] != etiqueta_conservada)
    # Lo que se eliminaría con la corrección (características + etiqueta).
    eliminada_corregida = df.duplicated(subset=[*caracteristicas, etiqueta], keep="first")

    en_duplicado = tam > 1
    conflictivo = n_etiquetas > 1

    grupos = df.groupby("grupo").agg(tam=(etiqueta, "size"), n_etiquetas=(etiqueta, "nunique"))
    grupos_dup = grupos[grupos["tam"] > 1]
    resumen = {
        "filas_tras_limpiar_inf_nan": int(len(df)),
        "grupos_totales": int(len(grupos)),
        "grupos_duplicados": int(len(grupos_dup)),
        "grupos_duplicado_seguro": int((grupos_dup["n_etiquetas"] == 1).sum()),
        "grupos_duplicado_conflictivo": int((grupos_dup["n_etiquetas"] > 1).sum()),
        "filas_en_grupos_conflictivos": int(conflictivo.sum()),
        "filas_eliminadas_criterio_actual": int(eliminada.sum()),
        "filas_eliminadas_con_etiqueta_distinta_a_la_conservada": int(perdida_de_etiqueta.sum()),
        "filas_eliminadas_criterio_corregido": int(eliminada_corregida.sum()),
    }

    por_etiqueta = pd.DataFrame({
        "filas_totales": df.groupby(etiqueta).size(),
        "filas_en_grupos_duplicados": df[en_duplicado].groupby(etiqueta).size(),
        "filas_en_grupos_conflictivos": df[conflictivo].groupby(etiqueta).size(),
        "filas_en_conflicto_con_BENIGN": df[conflictivo & tiene_benigno & (df[etiqueta] != benigno)]
        .groupby(etiqueta).size(),
        "en_conflictivos_no_primera_del_grupo": df[conflictivo & eliminada].groupby(etiqueta).size(),
        "eliminadas_criterio_actual": df[eliminada].groupby(etiqueta).size(),
        "eliminadas_con_otra_etiqueta_conservada": df[perdida_de_etiqueta].groupby(etiqueta).size(),
        "eliminadas_criterio_corregido": df[eliminada_corregida].groupby(etiqueta).size(),
    }).fillna(0).astype(int)
    por_etiqueta["quedan_criterio_actual"] = por_etiqueta["filas_totales"] - por_etiqueta["eliminadas_criterio_actual"]
    por_etiqueta["quedan_criterio_corregido"] = (
        por_etiqueta["filas_totales"] - por_etiqueta["eliminadas_criterio_corregido"])
    por_etiqueta = por_etiqueta.sort_values("filas_totales", ascending=False).reset_index(names="Label")

    conflictivas = df[conflictivo]
    combinaciones = (
        conflictivas.groupby("grupo")[etiqueta].agg(lambda s: " + ".join(sorted(s.unique())))
        .rename("combinacion").to_frame()
        .join(conflictivas.groupby("grupo").size().rename("filas"))
        .groupby("combinacion").agg(grupos=("filas", "size"), filas=("filas", "sum"))
        .sort_values("filas", ascending=False).reset_index()
    )
    return {"resumen": resumen, "por_etiqueta": por_etiqueta, "combinaciones": combinaciones}


def main() -> None:
    config = cargar_configuracion()
    caracteristicas = config["caracteristicas"]
    etiqueta = config["datos"]["columna_etiqueta"]
    benigno = config["datos"]["valor_benigno"]

    print("=== Auditoría de duplicados en evaluación ===")
    df = limpiar_sin_deduplicar(cargar_evaluacion(config), caracteristicas, etiqueta)
    res = auditar(df, caracteristicas, etiqueta, benigno)

    print("\n--- Resumen ---")
    for clave, valor in res["resumen"].items():
        print(f"  {clave:<58} {valor:>12,}")

    print("\n--- Combinaciones de etiquetas en grupos conflictivos ---")
    print(res["combinaciones"].to_string(index=False))

    print("\n--- Por etiqueta ---")
    with pd.option_context("display.width", 250, "display.max_columns", 20):
        print(res["por_etiqueta"].to_string(index=False))

    print("\n--- Ataques de volumen (recall 0 %) ---")
    tabla = res["por_etiqueta"].set_index("Label")
    for ataque in ATAQUES_DE_VOLUMEN:
        if ataque not in tabla.index:
            print(f"  {ataque}: no aparece")
            continue
        f = tabla.loc[ataque]
        print(f"  {ataque:<9} total={f['filas_totales']:,} | en conflicto con BENIGN={f['filas_en_conflicto_con_BENIGN']:,} "
              f"| eliminadas en favor de otra etiqueta={f['eliminadas_con_otra_etiqueta_conservada']:,} "
              f"| quedan hoy={f['quedan_criterio_actual']:,} → con corrección={f['quedan_criterio_corregido']:,}")

    directorio = config["rutas"]["reportes"]
    res["por_etiqueta"].to_csv(directorio / "auditoria_duplicados.csv", index=False)
    res["combinaciones"].to_csv(directorio / "auditoria_duplicados_combinaciones.csv", index=False)
    pd.DataFrame([res["resumen"]]).to_csv(directorio / "auditoria_duplicados_resumen.csv", index=False)
    print(f"\nGuardado en: {directorio / 'auditoria_duplicados.csv'} (+ _resumen y _combinaciones)")


if __name__ == "__main__":
    main()
