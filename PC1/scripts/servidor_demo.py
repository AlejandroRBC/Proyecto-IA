"""Servidor HTTP para la demo con PC2 (reemplaza levantar dos `python -m http.server` a mano).

Crea en datos/laboratorio/servidor_demo/:
  * prueba.txt  (pequeño): lo descarga PC2 en las fases normales.
  * grande.bin  (256 KB por defecto): lo descarga PC2 en la fase anómala del escenario mixto.
y sirve esa carpeta en los puertos 8000 (descargas) y 8080 (destino de las ráfagas).

Uso (desde PC1/):
    python scripts/servidor_demo.py
    python scripts/servidor_demo.py --tamano-kb 512
Se detiene con Ctrl+C. La primera vez Windows pregunta por el firewall: permitir en redes privadas.
"""

from __future__ import annotations

import argparse
import functools
import sys
import threading
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

RAIZ_PC1 = Path(__file__).resolve().parents[1]
CARPETA = RAIZ_PC1 / "datos" / "laboratorio" / "servidor_demo"

peticiones = {}
candado = threading.Lock()


class Manejador(SimpleHTTPRequestHandler):
    """Sirve archivos sin imprimir una línea por petición (las ráfagas harían cientos)."""

    def log_message(self, formato, *args):  # noqa: D401 — silencio intencional
        pass

    def log_request(self, code="-", size="-"):
        clave = (self.server.server_address[1], self.client_address[0], self.path, str(code))
        with candado:
            peticiones[clave] = peticiones.get(clave, 0) + 1


def preparar_archivos(tamano_kb: int) -> None:
    CARPETA.mkdir(parents=True, exist_ok=True)
    (CARPETA / "prueba.txt").write_text("hola desde PC1\n", encoding="utf-8")
    bloque = bytes(range(256))
    (CARPETA / "grande.bin").write_bytes(bloque * (tamano_kb * 1024 // len(bloque)))


def main() -> None:
    p = argparse.ArgumentParser(description="Servidor HTTP de la demo (puertos 8000 y 8080).")
    p.add_argument("--puertos", nargs="+", type=int, default=[8000, 8080])
    p.add_argument("--tamano-kb", type=int, default=256, help="Tamaño de grande.bin (por defecto 256 KB).")
    p.add_argument("--bind", default="0.0.0.0", help="Dirección donde escuchar (0.0.0.0 = todas).")
    args = p.parse_args()
    if not 1 <= args.tamano_kb <= 100_000:
        sys.exit("--tamano-kb debe estar entre 1 y 100000.")

    preparar_archivos(args.tamano_kb)
    manejador = functools.partial(Manejador, directory=str(CARPETA))
    servidores = []
    for puerto in args.puertos:
        try:
            servidor = ThreadingHTTPServer((args.bind, puerto), manejador)
        except OSError as e:
            for s in servidores:
                s.server_close()
            sys.exit(f"No se pudo abrir el puerto {puerto}: {e}\n"
                     f"¿Hay otro `python -m http.server` usando ese puerto? Ciérralo y vuelve a intentar.")
        servidor.daemon_threads = True
        threading.Thread(target=servidor.serve_forever, daemon=True).start()
        servidores.append(servidor)

    print(f"Sirviendo {CARPETA}")
    print(f"  prueba.txt ({(CARPETA / 'prueba.txt').stat().st_size} B) y grande.bin ({args.tamano_kb} KB)")
    print(f"  en {args.bind}, puertos {', '.join(map(str, args.puertos))}. Ctrl+C para detener.\n")
    try:
        while True:
            time.sleep(10)
            with candado:
                resumen = dict(peticiones)
                peticiones.clear()
            if resumen:
                print(time.strftime("%H:%M:%S"), "últimos 10 s:")
                for (puerto, cliente, ruta, codigo), n in sorted(resumen.items()):
                    print(f"  :{puerto}  {cliente:<15} {ruta:<14} {codigo}  x{n}")
    except KeyboardInterrupt:
        print("\nDeteniendo el servidor...")
    finally:
        for s in servidores:
            s.shutdown()
            s.server_close()


if __name__ == "__main__":
    main()
