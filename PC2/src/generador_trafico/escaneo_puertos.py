"""Escaneo de puertos de PC1 con nmap (instalado aparte, no es paquete de pip)."""

import shlex
import shutil
import subprocess
from pathlib import Path

from .configuracion import ErrorConfiguracion, validar_ip_destino

# Rutas típicas del instalador de Windows por si nmap no quedó en el PATH.
RUTAS_WINDOWS = [
    Path(r"C:\Program Files (x86)\Nmap\nmap.exe"),
    Path(r"C:\Program Files\Nmap\nmap.exe"),
]

# Opciones que permitirían escanear otros objetivos o leer objetivos de un archivo.
OPCIONES_PROHIBIDAS = ("-iL", "-iR", "--exclude", "--excludefile", "-p", "--script")


def buscar_nmap() -> str:
    """Ruta del ejecutable de nmap o error explicando cómo instalarlo."""
    ruta = shutil.which("nmap")
    if ruta:
        return ruta
    for candidata in RUTAS_WINDOWS:
        if candidata.is_file():
            return str(candidata)
    raise ErrorConfiguracion(
        "No se encontró nmap. Instálalo en PC2 desde https://nmap.org/download.html "
        "(no se instala con pip) y vuelve a intentarlo."
    )


def validar_argumentos_nmap(argumentos: str) -> list:
    """Solo se aceptan opciones (tokens que empiezan con '-'), nunca objetivos extra.

    Para opciones con valor usa la forma pegada, ej. '--max-retries=2' o '-T4'.
    """
    tokens = shlex.split(argumentos or "", posix=True)
    for token in tokens:
        if not token.startswith("-"):
            raise ErrorConfiguracion(
                f"'escaneo_puertos.argumentos_nmap' contiene '{token}', que no es una opción. "
                "El único objetivo permitido es la IP de PC1."
            )
        if any(token == p or token.startswith(p) for p in OPCIONES_PROHIBIDAS):
            raise ErrorConfiguracion(f"La opción de nmap '{token}' no está permitida en PC2.")
    return tokens


def armar_comando_nmap(config: dict, ejecutable: str = "nmap") -> list:
    """Construye el comando nmap con el rango y argumentos de la configuración."""
    ip = validar_ip_destino(config)
    ajustes = config.get("escaneo_puertos") or {}
    inicial = int(ajustes.get("puerto_inicial", 1))
    final = int(ajustes.get("puerto_final", 1024))
    if not 1 <= inicial <= final <= 65535:
        raise ErrorConfiguracion("Rango de puertos inválido: se requiere 1 <= puerto_inicial <= puerto_final <= 65535.")
    argumentos = validar_argumentos_nmap(ajustes.get("argumentos_nmap", "-sT"))
    return [ejecutable, *argumentos, "-p", f"{inicial}-{final}", ip]


def escanear_puertos(config: dict) -> dict:
    """Ejecuta nmap contra PC1, imprime un resumen y devuelve el resultado."""
    comando = armar_comando_nmap(config, buscar_nmap())
    print("  Ejecutando:", " ".join(comando))
    resultado = subprocess.run(comando, capture_output=True, text=True, errors="replace")
    if resultado.returncode != 0:
        raise ErrorConfiguracion(f"nmap terminó con código {resultado.returncode}: {resultado.stderr.strip()}")

    lineas = resultado.stdout.splitlines()
    abiertos = [l.strip() for l in lineas if "/tcp" in l and " open" in l]
    for linea in lineas:
        if "/tcp" in linea or "Nmap done" in linea or "Host is" in linea or "Not shown" in linea:
            print("   ", linea.strip())
    print(f"  Puertos abiertos encontrados: {len(abiertos)}")
    return {
        "comando": " ".join(comando[1:]),
        "puertos_abiertos": abiertos,
        "salida": resultado.stdout,
    }
