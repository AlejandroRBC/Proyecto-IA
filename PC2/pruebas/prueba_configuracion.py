"""Pruebas de configuración y límites de seguridad. No tocan la red real."""

import csv
import time

import pytest

from generador_trafico.configuracion import (
    LIMITE_ABSOLUTO_RAFAGA_SEGUNDOS,
    ErrorConfiguracion,
    calcular_duracion_efectiva,
    cargar_configuracion,
    validar_ip_destino,
    validar_parametros_rafaga,
)
from generador_trafico.escaneo_puertos import armar_comando_nmap, validar_argumentos_nmap
from generador_trafico.rafagas import generar_rafaga
from generador_trafico.registrador import COLUMNAS, ip_local_hacia, leer_ultimos_escenarios, registrar_escenario


def _config(ip="192.168.1.10", **rafagas):
    base = {"duracion_maxima_segundos": 30, "conexiones_por_segundo": 20,
            "puerto_destino": 8080, "concurrencia": 5}
    base.update(rafagas)
    return {"red": {"ip_destino_pc1": ip}, "rafagas": base,
            "escaneo_puertos": {"puerto_inicial": 1, "puerto_final": 1024, "argumentos_nmap": "-sT"}}


# ---------- IP destino ----------

@pytest.mark.parametrize("ip", ["", "   ", None])
def prueba_rechaza_ip_vacia(ip):
    with pytest.raises(ErrorConfiguracion, match="Falta la IP"):
        validar_ip_destino(_config(ip))


@pytest.mark.parametrize("ip", ["abc", "192.168.1", "300.1.1.1", "pc1.local", "192.168.1.10/24"])
def prueba_rechaza_ip_invalida(ip):
    with pytest.raises(ErrorConfiguracion, match="no es una dirección IP válida"):
        validar_ip_destino(_config(ip))


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1"])
def prueba_rechaza_ip_publica(ip):
    with pytest.raises(ErrorConfiguracion, match="pública"):
        validar_ip_destino(_config(ip))


@pytest.mark.parametrize("ip", ["0.0.0.0", "255.255.255.255", "224.0.0.1"])
def prueba_rechaza_ip_especial(ip):
    with pytest.raises(ErrorConfiguracion):
        validar_ip_destino(_config(ip))


@pytest.mark.parametrize("ip", ["192.168.1.10", "10.0.0.5", "172.16.3.4", "127.0.0.1"])
def prueba_acepta_ip_valida(ip):
    assert validar_ip_destino(_config(ip)) == ip


def prueba_yaml_vacio_desde_archivo(tmp_path):
    ruta = tmp_path / "configuracion.yaml"
    ruta.write_text('red:\n  ip_destino_pc1: ""\n', encoding="utf-8")
    with pytest.raises(ErrorConfiguracion):
        validar_ip_destino(cargar_configuracion(ruta))


def prueba_yaml_valido_desde_archivo(tmp_path):
    ruta = tmp_path / "configuracion.yaml"
    ruta.write_text('red:\n  ip_destino_pc1: "192.168.0.20"\n', encoding="utf-8")
    assert validar_ip_destino(cargar_configuracion(ruta)) == "192.168.0.20"


def prueba_yaml_del_repositorio_exige_completar_ip():
    """El configuracion.yaml versionado viene sin IP: debe negarse a ejecutar."""
    from pathlib import Path
    config = cargar_configuracion(Path(__file__).resolve().parents[1] / "configuracion.yaml")
    with pytest.raises(ErrorConfiguracion):
        validar_ip_destino(config)


# ---------- Límites de ráfaga ----------

def prueba_rafaga_rechaza_duracion_mayor_al_limite_absoluto():
    with pytest.raises(ErrorConfiguracion, match="límite absoluto"):
        validar_parametros_rafaga(_config(duracion_maxima_segundos=LIMITE_ABSOLUTO_RAFAGA_SEGUNDOS + 1))


@pytest.mark.parametrize("campo,valor", [
    ("duracion_maxima_segundos", 0), ("duracion_maxima_segundos", -5), ("duracion_maxima_segundos", "30"),
    ("conexiones_por_segundo", 0), ("conexiones_por_segundo", 10_000),
    ("puerto_destino", 0), ("puerto_destino", 70000), ("concurrencia", 0),
])
def prueba_rafaga_rechaza_parametros_invalidos(campo, valor):
    with pytest.raises(ErrorConfiguracion):
        validar_parametros_rafaga(_config(**{campo: valor}))


def prueba_rafaga_acepta_parametros_validos():
    assert validar_parametros_rafaga(_config())["duracion_maxima_segundos"] == 30


@pytest.mark.parametrize("solicitada,esperada", [(None, 30), (10, 10), (30, 30), (31, 30), (9999, 30)])
def prueba_duracion_efectiva_nunca_supera_el_maximo(solicitada, esperada):
    assert calcular_duracion_efectiva(solicitada, 30) == esperada


def prueba_duracion_efectiva_respeta_limite_absoluto_aunque_max_sea_mayor():
    assert calcular_duracion_efectiva(500, 500) == LIMITE_ABSOLUTO_RAFAGA_SEGUNDOS


def prueba_rafaga_corta_al_maximo_sin_red():
    """Con un 'conectar' falso: se piden 100 s, el máximo es 0.5 s y debe cortarse."""
    llamadas = []

    def conectar_falso(ip, puerto, timeout):
        llamadas.append((ip, puerto))
        return "exitosa"

    config = _config(duracion_maxima_segundos=0.5, conexiones_por_segundo=20)
    inicio = time.monotonic()
    resultado = generar_rafaga(config, duracion_solicitada=100, conectar=conectar_falso)
    assert time.monotonic() - inicio < 2
    assert resultado["duracion_efectiva_segundos"] == 0.5
    assert 0 < resultado["intentos"] <= 12
    assert all(destino == ("192.168.1.10", 8080) for destino in llamadas)


def prueba_rafaga_no_arranca_sin_ip():
    def conectar_prohibido(*_):
        raise AssertionError("no debió intentar conectar")

    with pytest.raises(ErrorConfiguracion):
        generar_rafaga(_config(ip=""), conectar=conectar_prohibido)


# ---------- nmap (solo armado del comando) ----------

def prueba_comando_nmap_apunta_solo_a_pc1():
    assert armar_comando_nmap(_config()) == ["nmap", "-sT", "-p", "1-1024", "192.168.1.10"]


@pytest.mark.parametrize("argumentos", ["-sT 8.8.8.8", "-iL objetivos.txt", "-iR 100", "-p-", "--script=vuln"])
def prueba_argumentos_nmap_no_permiten_otros_objetivos(argumentos):
    with pytest.raises(ErrorConfiguracion):
        validar_argumentos_nmap(argumentos)


# ---------- Registro CSV ----------

def prueba_registrador_crea_csv_con_encabezado(tmp_path):
    ruta = tmp_path / "sub" / "escenarios.csv"
    for tipo in ("a", "b"):
        registrar_escenario(ruta, {"fecha_hora_inicio": "i", "fecha_hora_fin": "f",
                                   "tipo_escenario": tipo, "parametros": {"x": 1}, "ip_destino": "10.0.0.1"})
    with open(ruta, newline="", encoding="utf-8") as archivo:
        filas = list(csv.DictReader(archivo))
    assert [f["tipo_escenario"] for f in filas] == ["a", "b"]
    assert filas[0]["parametros"] == '{"x": 1}'
    assert leer_ultimos_escenarios(ruta, 1)[0]["tipo_escenario"] == "b"


def prueba_registrador_respalda_csv_con_formato_anterior(tmp_path):
    ruta = tmp_path / "escenarios.csv"
    ruta.write_text("fecha_hora_inicio,fecha_hora_fin,tipo_escenario,parametros,ip_destino\n"
                    "i,f,viejo,{},10.0.0.1\n", encoding="utf-8")
    registrar_escenario(ruta, {"tipo_escenario": "nuevo", "ip_destino": "10.0.0.1", "ip_origen": "10.0.0.2"})
    with open(ruta, newline="", encoding="utf-8") as archivo:
        filas = list(csv.DictReader(archivo))
    assert list(filas[0].keys()) == COLUMNAS and filas[0]["ip_origen"] == "10.0.0.2"
    assert len(list(tmp_path.glob("escenarios.anterior-*.csv"))) == 1


def prueba_ip_local_hacia_loopback_no_envia_nada():
    assert ip_local_hacia("127.0.0.1") == "127.0.0.1"
