"""Ráfagas de conexiones TCP rápidas hacia PC1 (socket estándar, sin privilegios).

La ráfaga se corta SIEMPRE al llegar a la duración efectiva, que nunca supera
`rafagas.duracion_maxima_segundos` (ni el límite absoluto del programa).
"""

import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from .configuracion import calcular_duracion_efectiva, validar_ip_destino, validar_parametros_rafaga


def intentar_conexion(ip: str, puerto: int, timeout: float) -> str:
    """Abre y cierra una conexión TCP. Devuelve 'exitosa', 'rechazada' o 'error'."""
    try:
        with socket.create_connection((ip, puerto), timeout=timeout):
            return "exitosa"
    except ConnectionRefusedError:
        return "rechazada"
    except OSError:
        return "error"


def generar_rafaga(config: dict, duracion_solicitada=None, conectar=intentar_conexion) -> dict:
    """Lanza `conexiones_por_segundo` conexiones por segundo hasta agotar la duración.

    `conectar` se puede reemplazar en pruebas para no abrir conexiones reales.
    """
    ip = validar_ip_destino(config)
    parametros = validar_parametros_rafaga(config)
    duracion = calcular_duracion_efectiva(duracion_solicitada, parametros["duracion_maxima_segundos"])
    puerto = parametros["puerto_destino"]
    timeout = parametros["timeout_conexion_segundos"]
    periodo = 1.0 / parametros["conexiones_por_segundo"]

    conteo = {"exitosa": 0, "rechazada": 0, "error": 0, "omitida": 0}
    candado = threading.Lock()
    inicio = time.monotonic()
    fin = inicio + duracion

    def tarea():
        # No se conecta si ya se cumplió el tiempo (corte estricto).
        resultado = "omitida" if time.monotonic() >= fin else conectar(ip, puerto, min(timeout, max(fin - time.monotonic(), 0.05)))
        with candado:
            conteo[resultado] = conteo.get(resultado, 0) + 1

    interrumpida = False
    enviadas = 0
    ejecutor = ThreadPoolExecutor(max_workers=parametros["concurrencia"])
    try:
        siguiente = inicio
        while True:
            ahora = time.monotonic()
            if ahora >= fin:
                break
            if ahora < siguiente:
                time.sleep(min(siguiente - ahora, fin - ahora))
                continue
            ejecutor.submit(tarea)
            enviadas += 1
            siguiente += periodo
    except KeyboardInterrupt:
        interrumpida = True
        print("\n  Ráfaga interrumpida por el usuario.")
    finally:
        ejecutor.shutdown(wait=True, cancel_futures=True)

    transcurrido = time.monotonic() - inicio
    print(
        f"  Ráfaga a {ip}:{puerto} durante {transcurrido:.1f} s - intentos: {enviadas}, "
        f"exitosas: {conteo['exitosa']}, rechazadas: {conteo['rechazada']}, errores: {conteo['error']}"
    )
    return {
        "puerto_destino": puerto,
        "duracion_solicitada": duracion_solicitada,
        "duracion_efectiva_segundos": duracion,
        "conexiones_por_segundo": parametros["conexiones_por_segundo"],
        "concurrencia": parametros["concurrencia"],
        "intentos": enviadas,
        "exitosas": conteo["exitosa"],
        "rechazadas": conteo["rechazada"],
        "errores": conteo["error"],
        "interrumpida": interrumpida,
    }
