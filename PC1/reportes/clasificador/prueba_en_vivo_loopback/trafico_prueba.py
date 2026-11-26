"""Tráfico de prueba hacia 127.0.0.1: normal -> escaneo nmap -> ráfaga + descargas -> normal."""
import socket, subprocess, threading, time, urllib.request
def descargar(ruta):
    try:
        urllib.request.urlopen(f"http://127.0.0.1:8000{ruta}", timeout=5).read()
    except Exception as e:
        print("error", e)
def normal(seg):
    fin = time.time() + seg
    while time.time() < fin:
        descargar("/prueba.txt"); time.sleep(1.5)
print(time.strftime("%H:%M:%S"), "normal", flush=True); normal(12)
print(time.strftime("%H:%M:%S"), "nmap", flush=True)
subprocess.run(["nmap", "-sT", "-p", "1-300", "-T4", "127.0.0.1"], capture_output=True)
normal(8)
print(time.strftime("%H:%M:%S"), "rafaga + descargas", flush=True)
def rafaga(seg):
    fin = time.time() + seg
    while time.time() < fin:
        try:
            s = socket.create_connection(("127.0.0.1", 8080), timeout=2); s.close()
        except OSError:
            pass
        time.sleep(0.05)
def descargas(seg):
    fin = time.time() + seg
    while time.time() < fin:
        descargar("/grande.bin")
hilos = [threading.Thread(target=rafaga, args=(15,)), threading.Thread(target=descargas, args=(15,))]
[h.start() for h in hilos]; [h.join() for h in hilos]
print(time.strftime("%H:%M:%S"), "normal", flush=True); normal(10)
print(time.strftime("%H:%M:%S"), "fin", flush=True)
