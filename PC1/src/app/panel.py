"""Panel Streamlit de CyberGuard AI.

Uso (desde PC1/):  streamlit run src/app/panel.py

El panel no carga el modelo ni calcula puntajes. Lee los CSV que generan
``evaluar.py``, ``reproducir_flujos.py`` y ``capturar_en_vivo.py``, y lanza la
demo con CSV como subproceso. La captura en vivo se ejecuta aparte.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import matplotlib.pyplot as plt
import streamlit as st

# Permite importar el paquete ``src`` al ejecutar con ``streamlit run``.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.app import datos_panel as dp  # noqa: E402
from src.procesamiento.dataset import cargar_configuracion  # noqa: E402

st.set_page_config(page_title="CyberGuard AI", page_icon="🛡️", layout="wide")


def plt_cerrar() -> None:
    """Libera las figuras: la sección en vivo crea una cada pocos segundos."""
    plt.close("all")


@st.cache_data(show_spinner=False)
def cargar_estado_modelo(_config: dict):
    """Datos estáticos: se leen una vez al abrir el panel."""
    metricas, error_m = dp.leer_csv(_config["rutas"]["reportes"] / _config["archivos_salida"]["metricas"])
    por_tipo, error_t = dp.leer_csv(_config["rutas"]["reportes"] / _config["archivos_salida"]["metricas_por_tipo"])
    metadatos, error_meta = dp.leer_metadatos_modelo(_config)
    return metricas, error_m, por_tipo, error_t, metadatos, error_meta


try:
    config = cargar_configuracion()
except Exception as e:  # noqa: BLE001 — se muestra un mensaje claro en vez de un traceback
    st.error(f"No se pudo leer `configuracion.yaml`: {e}")
    st.stop()

metricas, error_metricas, por_tipo, error_por_tipo, metadatos, error_metadatos = cargar_estado_modelo(config)
umbral = dp.umbral_oficial(metadatos)

# ---------------------------------------------------------------------------
# Barra lateral: lanzar monitoreo
# ---------------------------------------------------------------------------
with st.sidebar:
    st.header("Lanzar monitoreo")
    st.caption("Reproduce flujos de CICIDS2017 como si llegaran en vivo, "
               "usando el detector y el umbral oficial.")

    archivos = dp.archivos_origen(config)
    hay_modelo = dp.modelo_disponible(config)
    if not archivos:
        st.warning(f"No se encontraron los CSV en `{config['rutas']['datos_crudos']}`.")
    if not hay_modelo:
        st.warning("El modelo no está entrenado: ejecuta `python scripts/ejecutar_experimentos.py`.")

    archivo = st.selectbox("Archivo de origen", archivos, disabled=not archivos)
    etiqueta = st.selectbox(
        "Filtrar por etiqueta (opcional)",
        [dp.TODAS_LAS_ETIQUETAS, *dp.etiquetas_conocidas(por_tipo)],
        help="Solo elige qué filas del archivo se reproducen; el modelo nunca recibe la etiqueta. "
             "Si la etiqueta no existe en ese archivo, no se procesa ningún flujo.",
    )
    filas = st.number_input("Flujos a procesar", min_value=1, max_value=5000, value=50, step=10)
    intervalo = st.slider("Intervalo entre flujos (segundos)", 0.0, 1.0, 0.0, 0.05,
                          help="Con 0 la corrida es inmediata. El panel queda en espera mientras corre.")
    semilla = st.number_input("Semilla", min_value=0, value=int(config["demo"]["semilla"]), step=1)

    st.caption("Para ver alertas reales en la exposición: **Wednesday** + **Heartbleed**, "
               "o **Thursday-…-Infilteration** + **Infiltration**.")

    if st.button("Iniciar monitoreo", type="primary", width="stretch",
                 disabled=not (archivos and hay_modelo)):
        comando = dp.construir_comando(archivo, filas, intervalo, semilla, etiqueta)
        entorno = {**os.environ, "PYTHONIOENCODING": "utf-8"}
        with st.spinner(f"Analizando {filas} flujos de {archivo}…"):
            try:
                proceso = subprocess.run(
                    comando, cwd=dp.RAIZ_PC1, env=entorno, capture_output=True, text=True,
                    encoding="utf-8", errors="replace", timeout=dp.tiempo_limite(filas, intervalo),
                )
                st.session_state["ultima_corrida"] = {
                    "codigo": proceso.returncode,
                    "salida": proceso.stdout,
                    "errores": proceso.stderr,
                }
            except subprocess.TimeoutExpired:
                st.session_state["ultima_corrida"] = {
                    "codigo": None, "salida": "", "errores": "La corrida superó el tiempo límite.",
                }

    st.divider()
    st.subheader("Limpiar historial")
    confirmar = st.checkbox("Confirmo que quiero borrar alertas.csv y flujos_analizados.csv")
    if st.button("Limpiar historial", disabled=not confirmar, width="stretch"):
        try:
            borrados = dp.borrar_historial(config)
            st.session_state["ultima_corrida"] = None
            st.success("Historial borrado." if borrados else "No había historial que borrar.")
        except OSError as e:
            st.error(f"No se pudo borrar el historial: {e}")

# ---------------------------------------------------------------------------
# Contenido principal
# ---------------------------------------------------------------------------
st.title("CyberGuard AI · Panel de monitoreo")
st.caption("Detección de anomalías en tráfico de red con Isolation Forest (modelo base, CICIDS2017).")

corrida = st.session_state.get("ultima_corrida")
if corrida:
    if corrida["codigo"] == 0:
        st.success("Monitoreo terminado. Las secciones de abajo ya muestran el historial actualizado.")
    elif corrida["codigo"] == 2:
        st.warning("No había flujos para reproducir con esos parámetros "
                   "(probablemente la etiqueta elegida no existe en ese archivo).")
    else:
        st.error("El monitoreo terminó con error. Revisa la salida de consola.")
    with st.expander("Salida de consola de la última corrida", expanded=False):
        st.code((corrida["salida"] or "") + ("\n" + corrida["errores"] if corrida["errores"] else ""),
                language="text")

# --- Monitoreo en vivo -------------------------------------------------------
st.header("Monitoreo en vivo")
captura_cfg = config.get("captura") or {}
st.caption("Tráfico real capturado en esta máquina por `scripts/capturar_en_vivo.py`, que se "
           "ejecuta aparte en otra terminal. Este panel solo lee los resultados.")
auto = st.toggle("Actualizar automáticamente", value=True,
                 help=f"Relee los resultados cada {captura_cfg.get('refresco_panel_segundos', 2)} s.")


@st.fragment(run_every=float(captura_cfg.get("refresco_panel_segundos", 2)) if auto else None)
def seccion_en_vivo() -> None:
    estado = dp.leer_estado_captura(config["rutas"]["estado_captura"])
    if dp.captura_activa(estado):
        st.success(f"Captura activa con el modelo **{estado.get('modelo', 'base')}** en "
                   f"**{estado['interfaz']}** · filtro `{estado['filtro']}` · "
                   f"desde {estado['inicio'][11:19]} · {estado['paquetes']:,} paquetes · "
                   f"{estado['flujos_activos']} flujos abiertos")
    else:
        ip_pc2 = captura_cfg.get("ip_pc2") or "<IP de PC2>"
        st.info("La captura no está corriendo. En otra terminal, desde `PC1/`:\n\n"
                "```\npython scripts/capturar_en_vivo.py\n```\n"
                f"(por defecto solo captura el tráfico con PC2, `{ip_pc2}`).")

    historial_vivo, _ = dp.leer_csv(config["rutas"]["flujos_analizados"])
    vivo = dp.flujos_en_vivo(historial_vivo)
    if vivo.empty:
        st.caption("Aún no hay flujos capturados en el historial.")
        return

    conteo_vivo = dp.conteos(vivo)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Flujos capturados", f"{conteo_vivo['total']:,}")
    c2.metric("Normales", f"{conteo_vivo['normales']:,}")
    c3.metric("Anómalos", f"{conteo_vivo['anomalos']:,}")
    c4.metric("No evaluables", f"{conteo_vivo['no_evaluables']:,}",
              help="Flujos de un solo paquete (duración 0): sus tasas por segundo son infinitas, "
                   "igual que en el dataset, y el modelo no los evalúa.")

    recientes = vivo.tail(300)
    umbral_vivo = dp.umbral_en_vivo(recientes, umbral)
    if umbral_vivo is not None and not dp.puntajes(recientes).empty:
        st.pyplot(dp.figura_puntajes(recientes, umbral_vivo), width="stretch")
        plt_cerrar()
        st.caption(f"Últimos 300 flujos capturados, en orden de llegada. La línea es el umbral del "
                   f"modelo usado en el flujo más reciente ({umbral_vivo:.4f}).")

    izquierda, derecha = st.columns([3, 2])
    with izquierda:
        st.subheader("Últimos flujos")
        st.dataframe(recientes[dp.COLUMNAS_VIVO].iloc[::-1].head(50), hide_index=True, width="stretch",
                     column_config={"score": st.column_config.NumberColumn(format="%.4f")})
    with derecha:
        st.subheader("Por IP de origen")
        st.dataframe(dp.resumen_por_ip_origen(vivo), hide_index=True, width="stretch",
                     column_config={"Proporción anómala": st.column_config.ProgressColumn(
                         format="percent", min_value=0.0, max_value=1.0)})

    anomalos_vivo = vivo[vivo["resultado"].astype(str) == "ANOMALO"]
    st.subheader(f"Alertas en vivo ({len(anomalos_vivo):,})")
    if anomalos_vivo.empty:
        st.caption("Ningún flujo capturado cruzó el umbral.")
    else:
        st.dataframe(anomalos_vivo[dp.COLUMNAS_VIVO].iloc[::-1].head(100), hide_index=True,
                     width="stretch", column_config={"score": st.column_config.NumberColumn(format="%.4f")})


seccion_en_vivo()

# --- Estado del modelo -------------------------------------------------------
st.header("Estado del modelo")
if metricas is None:
    st.info(f"{error_metricas} Ejecuta `python scripts/ejecutar_experimentos.py` para generarlo.")
else:
    m = metricas.iloc[0]
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Precision", f"{m['precision']:.4f}")
    c2.metric("Recall", f"{m['recall']:.4f}")
    c3.metric("F1", f"{m['f1']:.4f}")
    c4.metric("FPR", f"{m['fpr']:.2%}")
    if "roc_auc" in m:
        c5.metric("ROC-AUC", f"{m['roc_auc']:.3f}", help="Independiente del umbral; 0.5 = azar.")
    st.caption(f"Evaluado sobre {int(m['total_flujos']):,} flujos de martes a viernes. "
               + (f"Umbral oficial: {umbral:.6f}." if umbral is not None else ""))

st.subheader("Proporción detectada por tipo de Label")
if por_tipo is None:
    st.info(error_por_tipo)
else:
    st.dataframe(
        dp.tabla_por_tipo(por_tipo), hide_index=True, width="stretch",
        column_config={
            "Flujos": st.column_config.NumberColumn(format="localized"),
            "Marcados como anómalos": st.column_config.NumberColumn(format="localized"),
            "Proporción detectada": st.column_config.ProgressColumn(
                format="percent", min_value=0.0, max_value=1.0,
                help="En los ataques es el recall; en BENIGN es la tasa de falsos positivos."),
        },
    )
st.info(
    "**Limitación conocida.** El modelo detecta anomalías puntuales y raras (Heartbleed, parte de "
    "Infiltration), pero no ataques de volumen como PortScan, DDoS o DoS Hulk. Esos ataques forman "
    "grupos densos de flujos parecidos entre sí, e Isolation Forest no los aísla como raros. Es una "
    "limitación estructural del enfoque, no un error de calibración del umbral."
)

st.subheader("Modelo de laboratorio")
metricas_lab, _ = dp.leer_csv(config["rutas"]["reportes_laboratorio"] / "metricas.csv")
por_tipo_lab, _ = dp.leer_csv(config["rutas"]["reportes_laboratorio"] / "metricas_por_tipo.csv")
if metricas_lab is None:
    st.caption("Todavía no se entrenó: `python scripts/entrenar_modelo_laboratorio.py` "
               "(entrena con tráfico normal capturado en el laboratorio).")
else:
    st.caption("Entrenado solo con tráfico normal capturado en el laboratorio y evaluado con la "
               "validación normal + los ataques de PC2. Las mismas filas se evaluaron también con "
               "el modelo base para comparar.")
    st.dataframe(dp.tabla_metricas_laboratorio(metricas_lab), hide_index=True, width="stretch")
    if por_tipo_lab is not None:
        st.dataframe(dp.tabla_por_tipo_laboratorio(por_tipo_lab), hide_index=True, width="stretch",
                     column_config={c: st.column_config.ProgressColumn(format="percent", min_value=0.0,
                                                                       max_value=1.0)
                                    for c in ("base", "laboratorio")})
        st.caption("Proporción marcada como anómala por tipo: en los ataques es el recall; "
                   "en `normal` es la tasa de falsos positivos.")

# --- Monitoreo actual --------------------------------------------------------
st.header("Monitoreo actual")
historial, error_historial = dp.leer_csv(config["rutas"]["flujos_analizados"])
if historial is None:
    st.info("Todavía no se ha corrido ningún monitoreo. Usa **Iniciar monitoreo** en la barra lateral.")
else:
    conteo = dp.conteos(historial)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Flujos analizados", f"{conteo['total']:,}")
    c2.metric("Normales", f"{conteo['normales']:,}")
    c3.metric("Anómalos", f"{conteo['anomalos']:,}")
    c4.metric("No evaluables", f"{conteo['no_evaluables']:,}")

    if umbral is None:
        st.warning(error_metadatos)
    elif dp.puntajes(historial).empty:
        st.info("El historial no tiene puntajes para graficar.")
    else:
        st.subheader("Puntaje por flujo")
        st.pyplot(dp.figura_puntajes(historial, umbral), width="stretch")
        st.caption("Cada punto es un flujo en orden de llegada. Los que quedan por debajo de la línea "
                   "punteada (umbral oficial) son anómalos y se marcan con una X roja.")

    st.subheader("Últimas alertas")
    alertas, _ = dp.leer_csv(config["rutas"]["alertas"])
    if alertas is None:
        st.info("No hay alertas registradas: ningún flujo analizado cruzó el umbral.")
    else:
        columnas = [c for c in ["fecha_hora", "id_flujo", "ip_origen", "ip_destino", "puerto_destino",
                                 "score", "resultado"]
                    if c in alertas.columns]
        st.dataframe(alertas[columnas].iloc[::-1].head(100), hide_index=True, width="stretch",
                     column_config={"score": st.column_config.NumberColumn(format="%.4f")})
        st.caption(f"{len(alertas):,} alertas en total; se muestran las 100 más recientes primero.")

# --- Explorador de umbral ----------------------------------------------------
st.header("Explorador de umbral")
st.warning("Esto es solo exploración visual sobre el historial ya analizado. "
           "No cambia el umbral oficial del modelo ni las alertas guardadas.")
scores = dp.puntajes(historial) if historial is not None else None
if scores is None or scores.empty or umbral is None:
    st.info("Hace falta un historial con puntajes (corre un monitoreo primero).")
else:
    minimo = float(min(scores.min(), umbral))
    maximo = float(max(scores.max(), umbral))
    if minimo == maximo:
        maximo = minimo + 0.01
    hipotetico = st.slider("Umbral hipotético", min_value=minimo, max_value=maximo,
                           value=float(umbral), step=(maximo - minimo) / 200, format="%.4f")
    oficial_n = dp.contar_anomalos_con_umbral(scores, umbral)
    hipotetico_n = dp.contar_anomalos_con_umbral(scores, hipotetico)
    c1, c2, c3 = st.columns(3)
    c1.metric("Anómalos con el umbral oficial", f"{oficial_n:,}", help=f"Umbral {umbral:.4f}")
    c2.metric("Anómalos con el umbral hipotético", f"{hipotetico_n:,}",
              delta=f"{hipotetico_n - oficial_n:+,}", delta_color="off")
    c3.metric("Proporción marcada (hipotético)", f"{hipotetico_n / len(scores):.1%}")
    st.pyplot(dp.figura_puntajes(historial, umbral, hipotetico), width="stretch")
