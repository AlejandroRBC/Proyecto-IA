"""Tráfico normal: ping hacia PC1 y descarga HTTP opcional."""

import platform
import subprocess
import time
import urllib.request
from urllib.parse import urlparse

from .configuracion import ErrorConfiguracion, validar_ip_destino


def _comando_ping(ip: str) -> list:
    """Un solo eco ICMP, con la sintaxis del sistema operativo."""
    if platform.system() == "Windows":
        return ["ping", "-n", "1", "-w", "1000", ip]
    return ["ping", "-c", "1", "-W", "1", ip]


def enviar_ping(config: dict) -> dict:
    """Envía `ping.cantidad` ecos a PC1, uno cada `ping.intervalo_segundos`.

    Se lanza un ping por eco (en vez de `ping -n N`) para respetar el intervalo
    configurado también en Windows, cuyo ping no permite cambiarlo.
    """
    ip = validar_ip_destino(config)
    ajustes = config.get("ping") or {}
    cantidad = int(ajustes.get("cantidad", 10))
    intervalo = float(ajustes.get("intervalo_segundos", 1))
    if cantidad <= 0 or intervalo < 0:
        raise ErrorConfiguracion("'ping.cantidad' debe ser > 0 y 'ping.intervalo_segundos' >= 0.")

    respuestas = 0
    for numero in range(1, cantidad + 1):
        resultado = subprocess.run(_comando_ping(ip), capture_output=True, text=True, errors="replace")
        # En Windows "Destination host unreachable" devuelve código 0, por eso se busca "TTL".
        ok = resultado.returncode == 0 and "ttl" in resultado.stdout.lower()
        respuestas += ok
        print(f"  Ping {numero}/{cantidad} a {ip}: {'respuesta' if ok else 'sin respuesta'}")
        if numero < cantidad:
            time.sleep(intervalo)

    print(f"  Resumen: {respuestas}/{cantidad} respuestas recibidas.")
    return {"cantidad": cantidad, "intervalo_segundos": intervalo, "respuestas": respuestas}


def construir_url_http(config: dict) -> str:
    """URL del servidor HTTP de PC1 a partir de la configuración."""
    ip = validar_ip_destino(config)
    ajustes = config.get("http") or {}
    puerto = int(ajustes.get("puerto", 8000))
    ruta = str(ajustes.get("ruta", "/"))
    if not ruta.startswith("/"):
        ruta = "/" + ruta
    host = f"[{ip}]" if ":" in ip else ip
    return f"http://{host}:{puerto}{ruta}"


def ping_una_vez(ip: str) -> bool:
    """Un solo eco ICMP hacia ``ip`` (ya validada). Devuelve si hubo respuesta."""
    resultado = subprocess.run(_comando_ping(ip), capture_output=True, text=True, errors="replace")
    return resultado.returncode == 0 and "ttl" in resultado.stdout.lower()


def construir_url_archivo(config: dict, ruta: str) -> str:
    """URL de un archivo concreto del servidor HTTP de PC1 (mismo puerto que http.puerto)."""
    ip = validar_ip_destino(config)
    puerto = int((config.get("http") or {}).get("puerto", 8000))
    ruta = ruta if ruta.startswith("/") else "/" + ruta
    host = f"[{ip}]" if ":" in ip else ip
    return f"http://{host}:{puerto}{ruta}"


def descargar_archivo_http(config: dict, url: str, silencioso: bool = False) -> dict:
    """Descarga `url` (solo si apunta a PC1). Requiere `python -m http.server` en PC1."""
    ip = validar_ip_destino(config)
    partes = urlparse(url)
    if partes.scheme != "http" or partes.hostname != ip:
        raise ErrorConfiguracion(f"La URL '{url}' no apunta a PC1 ({ip}) por http; se cancela la descarga.")
    timeout = float((config.get("http") or {}).get("timeout_segundos", 5))
    inicio = time.monotonic()
    with urllib.request.urlopen(url, timeout=timeout) as respuesta:
        contenido = respuesta.read()
        estado = respuesta.status
    segundos = time.monotonic() - inicio
    if not silencioso:
        print(f"  Descarga HTTP {url}: estado {estado}, {len(contenido)} bytes en {segundos:.2f} s.")
    return {"url": url, "estado": estado, "bytes": len(contenido)}
