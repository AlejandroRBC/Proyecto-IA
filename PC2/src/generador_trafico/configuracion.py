"""Carga de configuracion.yaml y validaciones de seguridad.

Toda la generación de tráfico depende de `validar_ip_destino`: si la IP de PC1
no está configurada o no es válida, ningún escenario se ejecuta.
"""

import ipaddress
from pathlib import Path

import yaml

# Tope absoluto para ráfagas, independiente de lo que diga el YAML.
LIMITE_ABSOLUTO_RAFAGA_SEGUNDOS = 60
LIMITE_CONEXIONES_POR_SEGUNDO = 200
LIMITE_CONCURRENCIA = 50


class ErrorConfiguracion(Exception):
    """Error de configuración con un mensaje pensado para el usuario."""


def cargar_configuracion(ruta) -> dict:
    """Lee el YAML y guarda la carpeta base para resolver rutas relativas."""
    ruta = Path(ruta)
    if not ruta.is_file():
        raise ErrorConfiguracion(f"No se encontró el archivo de configuración: {ruta}")
    with open(ruta, encoding="utf-8") as archivo:
        config = yaml.safe_load(archivo) or {}
    if not isinstance(config, dict):
        raise ErrorConfiguracion("configuracion.yaml no tiene el formato esperado (debe ser un mapa).")
    config["_carpeta_base"] = str(ruta.resolve().parent)
    return config


def validar_ip_destino(config: dict) -> str:
    """Devuelve la IP de PC1 si es válida; si no, lanza ErrorConfiguracion.

    Se exige además que sea una IP privada o de loopback, para que el tráfico
    nunca salga hacia redes externas.
    """
    valor = ((config or {}).get("red") or {}).get("ip_destino_pc1")
    if valor is None or str(valor).strip() == "":
        raise ErrorConfiguracion(
            "Falta la IP de PC1: completa 'red.ip_destino_pc1' en configuracion.yaml "
            "con la IP de PC1 en la red de laboratorio (ej. \"192.168.1.10\")."
        )
    texto = str(valor).strip()
    try:
        ip = ipaddress.ip_address(texto)
    except ValueError:
        raise ErrorConfiguracion(
            f"'red.ip_destino_pc1' = '{texto}' no es una dirección IP válida."
        ) from None
    if ip.is_unspecified or ip.is_multicast or ip.is_reserved or (ip.version == 4 and texto == "255.255.255.255"):
        raise ErrorConfiguracion(f"La IP '{texto}' no apunta a un único equipo (es especial/difusión).")
    if not (ip.is_private or ip.is_loopback or ip.is_link_local):
        raise ErrorConfiguracion(
            f"La IP '{texto}' es pública. PC2 solo genera tráfico hacia la red de laboratorio "
            "(IPs privadas o 127.0.0.1)."
        )
    return texto


def _entero(seccion: dict, clave: str, nombre: str) -> int:
    valor = seccion.get(clave)
    if isinstance(valor, bool) or not isinstance(valor, (int, float)):
        raise ErrorConfiguracion(f"'{nombre}' debe ser un número (valor actual: {valor!r}).")
    return valor


def validar_parametros_rafaga(config: dict) -> dict:
    """Valida la sección 'rafagas' sin abrir ninguna conexión.

    Devuelve un dict normalizado con los parámetros listos para usar.
    """
    rafagas = (config or {}).get("rafagas") or {}
    duracion = _entero(rafagas, "duracion_maxima_segundos", "rafagas.duracion_maxima_segundos")
    if duracion <= 0:
        raise ErrorConfiguracion("'rafagas.duracion_maxima_segundos' debe ser mayor que 0.")
    if duracion > LIMITE_ABSOLUTO_RAFAGA_SEGUNDOS:
        raise ErrorConfiguracion(
            f"'rafagas.duracion_maxima_segundos' = {duracion} supera el límite absoluto de "
            f"{LIMITE_ABSOLUTO_RAFAGA_SEGUNDOS} s permitido por el programa."
        )
    cps = _entero(rafagas, "conexiones_por_segundo", "rafagas.conexiones_por_segundo")
    if not 0 < cps <= LIMITE_CONEXIONES_POR_SEGUNDO:
        raise ErrorConfiguracion(
            f"'rafagas.conexiones_por_segundo' debe estar entre 1 y {LIMITE_CONEXIONES_POR_SEGUNDO}."
        )
    puerto = _entero(rafagas, "puerto_destino", "rafagas.puerto_destino")
    if not 1 <= puerto <= 65535:
        raise ErrorConfiguracion("'rafagas.puerto_destino' debe estar entre 1 y 65535.")
    concurrencia = rafagas.get("concurrencia", 10)
    if isinstance(concurrencia, bool) or not isinstance(concurrencia, int) or not 1 <= concurrencia <= LIMITE_CONCURRENCIA:
        raise ErrorConfiguracion(f"'rafagas.concurrencia' debe ser un entero entre 1 y {LIMITE_CONCURRENCIA}.")
    timeout = rafagas.get("timeout_conexion_segundos", 1)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 10:
        raise ErrorConfiguracion("'rafagas.timeout_conexion_segundos' debe estar entre 0 y 10.")
    return {
        "duracion_maxima_segundos": duracion,
        "conexiones_por_segundo": cps,
        "puerto_destino": int(puerto),
        "concurrencia": concurrencia,
        "timeout_conexion_segundos": timeout,
    }


LIMITE_ABSOLUTO_MIXTO_SEGUNDOS = 1800  # 30 min: tope del escenario mixto aunque el YAML diga más
FASES_MIXTO = ("normal_inicial", "anomala", "normal_final")


def validar_parametros_mixto(config: dict) -> dict:
    """Valida la sección 'mixto' sin generar tráfico. Devuelve los parámetros normalizados."""
    mixto = (config or {}).get("mixto") or {}

    def numero(clave, defecto, minimo, maximo):
        valor = mixto.get(clave, defecto)
        if isinstance(valor, bool) or not isinstance(valor, (int, float)) or not minimo <= valor <= maximo:
            raise ErrorConfiguracion(f"'mixto.{clave}' debe ser un número entre {minimo} y {maximo} "
                                     f"(valor actual: {valor!r}).")
        return valor

    maxima = numero("duracion_total_maxima_segundos", 900, 10, LIMITE_ABSOLUTO_MIXTO_SEGUNDOS)
    total = numero("duracion_total_segundos", 300, 3, maxima)
    proporciones = mixto.get("proporciones", [0.4, 0.2, 0.4])
    if (not isinstance(proporciones, list) or len(proporciones) != 3
            or any(isinstance(p, bool) or not isinstance(p, (int, float)) or p <= 0 for p in proporciones)
            or abs(sum(proporciones) - 1) > 0.01):
        raise ErrorConfiguracion("'mixto.proporciones' debe ser una lista de 3 números positivos que sumen 1 "
                                 "(normal inicial, anómala, normal final), ej. [0.4, 0.2, 0.4].")
    pausa_min = numero("pausa_normal_min_segundos", 1, 0, 60)
    pausa_max = numero("pausa_normal_max_segundos", 4, 0, 60)
    if pausa_min > pausa_max:
        raise ErrorConfiguracion("'mixto.pausa_normal_min_segundos' no puede ser mayor que la máxima.")
    for clave in ("archivo_normal", "archivo_grande"):
        if not str(mixto.get(clave, "")).strip():
            raise ErrorConfiguracion(f"Falta 'mixto.{clave}' (ruta del archivo en el servidor HTTP de PC1).")
    return {
        "duracion_total_segundos": float(total),
        "duracion_total_maxima_segundos": float(maxima),
        "proporciones": [float(p) for p in proporciones],
        "archivo_normal": str(mixto["archivo_normal"]),
        "archivo_grande": str(mixto["archivo_grande"]),
        "descargas_paralelas": int(numero("descargas_paralelas", 3, 1, 10)),
        "pausa_normal_min_segundos": float(pausa_min),
        "pausa_normal_max_segundos": float(pausa_max),
        "pausa_anomala_segundos": float(numero("pausa_anomala_segundos", 0.2, 0, 10)),
        "incluir_rafaga": bool(mixto.get("incluir_rafaga", True)),
    }


def planificar_fases(config: dict, total=None) -> list:
    """Fases del escenario mixto como [(nombre, segundos)]; la duración se recorta al máximo."""
    parametros = validar_parametros_mixto(config)
    if total is None:
        total = parametros["duracion_total_segundos"]
    total = float(total)
    if total <= 0:
        raise ErrorConfiguracion("La duración del escenario mixto debe ser mayor que 0.")
    total = min(total, parametros["duracion_total_maxima_segundos"], LIMITE_ABSOLUTO_MIXTO_SEGUNDOS)
    return [(nombre, total * p) for nombre, p in zip(FASES_MIXTO, parametros["proporciones"])]


def calcular_duracion_efectiva(duracion_solicitada, duracion_maxima) -> float:
    """Recorta siempre la duración pedida al máximo configurado (y al límite absoluto)."""
    tope = min(float(duracion_maxima), float(LIMITE_ABSOLUTO_RAFAGA_SEGUNDOS))
    if duracion_solicitada is None:
        return tope
    solicitada = float(duracion_solicitada)
    if solicitada <= 0:
        raise ErrorConfiguracion("La duración de la ráfaga debe ser mayor que 0.")
    return min(solicitada, tope)


def ruta_registro(config: dict) -> Path:
    """Ruta absoluta del CSV de escenarios (relativa a la carpeta del YAML)."""
    ruta = Path(((config or {}).get("registro") or {}).get("ruta_csv") or "registros/escenarios_ejecutados.csv")
    if not ruta.is_absolute():
        ruta = Path(config.get("_carpeta_base", ".")) / ruta
    return ruta
