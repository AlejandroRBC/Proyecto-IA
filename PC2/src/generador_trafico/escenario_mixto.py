"""Escenario mixto para la presentación: tráfico normal → tráfico anómalo → tráfico normal.

* Fases normales: ping suelto + descarga de un archivo pequeño de PC1, con pausas
  aleatorias (como un usuario que navega).
* Fase anómala: varias descargas en paralelo y seguidas de un archivo de ~256 KB
  (transferencias rápidas y voluminosas) y, si está activado, ráfagas de conexiones TCP.

Por qué estas descargas: al calibrar con capturas reales, el modelo base marcó como
ANOMALO el 100 % de las descargas de 256 KB y el 0 % de los GET pequeños. La ráfaga
se incluye porque es el "ataque" del proyecto, pero conexión a conexión parece normal
y el modelo casi nunca la marca (limitación documentada).

Cada fase se anota en el CSV de escenarios como una fila propia (``mixto_normal`` o
``mixto_anomalo``) para que PC1 pueda cruzar los flujos capturados con las fases.
Todo el tráfico va solo a la IP de PC1 validada en configuracion.yaml.
"""

import random
import threading
import time

from .configuracion import (
    ErrorConfiguracion,
    planificar_fases,
    ruta_registro,
    validar_ip_destino,
    validar_parametros_mixto,
    validar_parametros_rafaga,
)
from .rafagas import generar_rafaga
from .registrador import ahora, ip_local_hacia, registrar_escenario
from .trafico_normal import (
    construir_url_archivo,
    consultar_tamano_http,
    descargar_archivo_http,
    ping_una_vez,
)

TIPO_NORMAL = "mixto_normal"
TIPO_ANOMALO = "mixto_anomalo"


TAMANO_MINIMO_GRANDE_BYTES = 100_000   # por debajo de esto no es el grande.bin de la demo


def verificar_servidor(config: dict, consultar=None) -> dict:
    """Comprueba, antes de empezar, que PC1 sirve de verdad el archivo normal y el grande.

    Un servidor equivocado (p. ej. un ``python -m http.server`` abierto en otra carpeta)
    responde 404: el escenario correría sin generar ninguna transferencia grande y el
    panel no mostraría alertas.

    Solo pide el tamaño (HEAD), sin descargar el archivo: una descarga completa de
    grande.bin aquí aparecía como una alerta en plena fase normal.
    """
    ip = validar_ip_destino(config)
    parametros = validar_parametros_mixto(config)
    consultar = consultar or (lambda url: consultar_tamano_http(config, url))
    tamanos = {}
    for clave in ("archivo_normal", "archivo_grande"):
        ruta = parametros[clave]
        url = construir_url_archivo(config, ruta)
        try:
            tamanos[clave] = int(consultar(url))
        except OSError as e:
            raise ErrorConfiguracion(
                f"PC1 ({ip}) no entrega {ruta}: {e}. En PC1 ejecuta `python scripts/servidor_demo.py` "
                "(y cierra cualquier otro `http.server` abierto en los puertos 8000 y 8080).") from None
    if tamanos["archivo_grande"] < TAMANO_MINIMO_GRANDE_BYTES:
        raise ErrorConfiguracion(
            f"{parametros['archivo_grande']} mide solo {tamanos['archivo_grande']} bytes: no es el archivo "
            "grande de la demo y no habrá alertas. En PC1 cierra los `http.server` abiertos y ejecuta "
            "`python scripts/servidor_demo.py`.")
    return tamanos


class Contador:
    """Contadores compartidos entre hilos."""

    def __init__(self):
        self._valores = {}
        self._candado = threading.Lock()
        self.primer_error = None

    def sumar(self, clave: str, cantidad: int = 1) -> None:
        with self._candado:
            self._valores[clave] = self._valores.get(clave, 0) + cantidad

    def error(self, excepcion: Exception) -> None:
        self.sumar("errores")
        with self._candado:
            if self.primer_error is None:
                self.primer_error = f"{type(excepcion).__name__}: {excepcion}"

    def valores(self) -> dict:
        with self._candado:
            return dict(self._valores)


def acciones_reales(config: dict) -> dict:
    """Las acciones de red del escenario (en pruebas se reemplazan por funciones falsas)."""
    ip = validar_ip_destino(config)
    parametros = validar_parametros_mixto(config)
    url_normal = construir_url_archivo(config, parametros["archivo_normal"])
    url_grande = construir_url_archivo(config, parametros["archivo_grande"])
    return {
        "ping": lambda: ping_una_vez(ip),
        "get_normal": lambda: descargar_archivo_http(config, url_normal, silencioso=True),
        "get_grande": lambda: descargar_archivo_http(config, url_grande, silencioso=True),
        "rafaga": lambda segundos, detener: generar_rafaga(config, segundos, detener=detener),
    }


def _esperar(parar: threading.Event, segundos: float) -> None:
    if segundos > 0:
        parar.wait(segundos)


def _trabajador_normal(acciones, parametros, fin, parar, conteo):
    while not parar.is_set() and time.monotonic() < fin:
        try:
            conteo.sumar("pings")
            if acciones["ping"]():
                conteo.sumar("pings_con_respuesta")
        except Exception as e:  # noqa: BLE001 — un fallo suelto no detiene el escenario
            conteo.error(e)
        try:
            acciones["get_normal"]()
            conteo.sumar("descargas_pequenas")
        except Exception as e:  # noqa: BLE001
            conteo.error(e)
        pausa = random.uniform(parametros["pausa_normal_min_segundos"], parametros["pausa_normal_max_segundos"])
        _esperar(parar, min(pausa, fin - time.monotonic()))


def _trabajador_descargas(acciones, parametros, fin, parar, conteo):
    while not parar.is_set() and time.monotonic() < fin:
        try:
            acciones["get_grande"]()
            conteo.sumar("descargas_grandes")
        except Exception as e:  # noqa: BLE001
            conteo.error(e)
        _esperar(parar, min(parametros["pausa_anomala_segundos"], fin - time.monotonic()))


def _trabajador_rafagas(acciones, fin, parar, conteo):
    # Cada ráfaga respeta su propio tope (rafagas.duracion_maxima_segundos); se encadenan
    # hasta cubrir la fase anómala.
    while not parar.is_set() and fin - time.monotonic() > 1:
        try:
            resultado = acciones["rafaga"](fin - time.monotonic(), parar)
            conteo.sumar("rafagas")
            conteo.sumar("conexiones_rafaga", int((resultado or {}).get("intentos", 0)))
        except Exception as e:  # noqa: BLE001
            conteo.error(e)
            _esperar(parar, 1)


def _correr_fase(nombre, segundos, parametros, acciones, intervalo_progreso):
    """Ejecuta una fase. Devuelve (contadores, interrumpida). Ctrl+C la corta limpio."""
    fin = time.monotonic() + segundos
    parar = threading.Event()
    conteo = Contador()
    if nombre == "anomala":
        hilos = [threading.Thread(target=_trabajador_descargas, args=(acciones, parametros, fin, parar, conteo),
                                  daemon=True) for _ in range(parametros["descargas_paralelas"])]
        if parametros["incluir_rafaga"]:
            hilos.append(threading.Thread(target=_trabajador_rafagas, args=(acciones, fin, parar, conteo),
                                          daemon=True))
    else:
        hilos = [threading.Thread(target=_trabajador_normal, args=(acciones, parametros, fin, parar, conteo),
                                  daemon=True)]
    for hilo in hilos:
        hilo.start()

    interrumpida = False
    siguiente_aviso = time.monotonic() + intervalo_progreso
    try:
        # time.sleep en el hilo principal: así Ctrl+C se atiende al momento en Windows.
        while time.monotonic() < fin:
            time.sleep(min(0.25, max(fin - time.monotonic(), 0)))
            if time.monotonic() >= siguiente_aviso:
                restante = max(fin - time.monotonic(), 0)
                detalle = ", ".join(f"{k}={v}" for k, v in sorted(conteo.valores().items()))
                print(f"  [{nombre}] quedan {restante:4.0f} s | {detalle or 'arrancando...'}")
                siguiente_aviso += intervalo_progreso
    except KeyboardInterrupt:
        interrumpida = True
        print(f"\n  Escenario mixto interrumpido durante la fase '{nombre}'.")
    finally:
        parar.set()
        for hilo in hilos:
            hilo.join(timeout=10)
    return conteo, interrumpida


def ejecutar_escenario_mixto(config: dict, total=None, acciones=None, registrar=True,
                             intervalo_progreso: float = 5.0) -> list:
    """Corre las tres fases y devuelve una fila de resumen por fase (registradas en el CSV)."""
    ip = validar_ip_destino(config)
    parametros = validar_parametros_mixto(config)
    if parametros["incluir_rafaga"]:
        validar_parametros_rafaga(config)
    fases = planificar_fases(config, total)
    acciones = acciones or acciones_reales(config)
    ip_origen = ip_local_hacia(ip)

    filas = []
    for nombre, segundos in fases:
        tipo = TIPO_ANOMALO if nombre == "anomala" else TIPO_NORMAL
        print(f"\n  >>> Fase '{nombre}' ({'ANÓMALA' if tipo == TIPO_ANOMALO else 'normal'}) "
              f"durante {segundos:.0f} s")
        inicio = ahora()
        conteo, interrumpida = _correr_fase(nombre, segundos, parametros, acciones, intervalo_progreso)
        fila = {
            "fecha_hora_inicio": inicio,
            "fecha_hora_fin": ahora(),
            "tipo_escenario": tipo,
            "parametros": {"fase": nombre, "duracion_planificada_segundos": round(segundos, 1),
                           **conteo.valores(), "interrumpida": interrumpida},
            "ip_destino": ip,
            "ip_origen": ip_origen,
        }
        if conteo.primer_error:
            print(f"  Aviso: hubo errores en la fase '{nombre}' (primero: {conteo.primer_error}). "
                  "¿Está corriendo el servidor HTTP en PC1?")
        if registrar:
            registrar_escenario(ruta_registro(config), fila)
        filas.append(fila)
        print(f"  Fase '{nombre}' terminada: {fila['parametros']}")
        if interrumpida:
            break
    return filas
