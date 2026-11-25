# PC2 — Generador de tráfico de laboratorio

PC2 genera tráfico de prueba **exclusivamente hacia PC1** (normal y simulando ataques) y deja
constancia en un CSV de cuándo y con qué parámetros lo hizo, para correlacionarlo después con
lo que se registre en PC1.

> **Importante:** PC2 **no reemplaza la captura real en PC1**. La captura de flujos con
> CICFlowMeter en PC1 sigue pendiente (fase futura). PC2 solo genera el tráfico y anota cuándo lo hizo.

## Requisitos

1. Python 3.10 o superior.
2. Dependencias de Python:
   ```
   pip install -r requirements.txt
   ```
   Solo `pyyaml` (configuración) y `pytest` (pruebas). La descarga HTTP usa `urllib` de la
   librería estándar, por eso no se usa `requests`.
3. **nmap instalado en PC2** (requisito externo, no se instala con pip):
   descargar desde <https://nmap.org/download.html>. En Windows el instalador lo agrega al PATH;
   el programa también lo busca en `C:\Program Files (x86)\Nmap\`. Verificar con `nmap --version`.
   Sin nmap, las demás opciones funcionan y la de escaneo muestra un aviso.

## Configurar la IP de PC1

Editar `configuracion.yaml` y completar:

```yaml
red:
  ip_destino_pc1: "192.168.1.10"   # IP real de PC1 en la red de laboratorio
```

Reglas de seguridad que aplica el programa:

- Si la IP está vacía o no es válida, **ningún escenario se ejecuta** y se explica qué falta.
- Solo se aceptan IPs privadas (10.x, 172.16–31.x, 192.168.x) o `127.0.0.1`; las públicas se rechazan.
- Antes del escaneo y de la ráfaga se muestra la IP destino y se pide confirmación `s/n`.
- La ráfaga se corta siempre en `rafagas.duracion_maxima_segundos` (por defecto 30 s), aunque se
  pida más tiempo. El programa además rechaza configurar un máximo superior a 60 s.
- `argumentos_nmap` solo admite opciones (ej. `-sT -T4 --open`); no se pueden añadir otros
  objetivos ni `-iL`, `-iR`, `-p` o `--script`. Para opciones con valor usar la forma pegada,
  ej. `--max-retries=2`.

La configuración se recarga en cada opción del menú: se puede editar el YAML sin reiniciar.

## Uso

```
cd PC2
python menu.py
```

(Opcional: `python menu.py --config otra_configuracion.yaml`.)

| Opción | Escenario | Qué hace |
|---|---|---|
| 1 | Tráfico normal | `ping` del sistema hacia PC1 (`ping.cantidad` ecos, uno cada `ping.intervalo_segundos`). Luego ofrece una descarga HTTP opcional. |
| 2 | Escaneo de puertos | `nmap <argumentos_nmap> -p <inicial>-<final> <IP de PC1>` (por defecto `-sT`, puertos 1-1024; TCP connect, sin privilegios de administrador). Pide confirmación. |
| 3 | Ráfaga de conexiones | Conexiones TCP rápidas y sucesivas con `socket` (sin Npcap ni administrador) a `rafagas.puerto_destino`, a `conexiones_por_segundo`, con `concurrencia` hilos, durante la duración indicada (máximo `duracion_maxima_segundos`). Pide confirmación. Ctrl+C la detiene antes. |
| 4 | Ver registro | Muestra los últimos 10 escenarios del CSV. |
| 5 | Salir | |

### Descarga HTTP opcional (requisito manual en PC1)

Para que la descarga funcione, en PC1 hay que iniciar a mano un servidor HTTP, por ejemplo en la
carpeta con algún archivo de prueba:

```
python -m http.server 8000
```

PC2 descarga `http://<IP de PC1>:<http.puerto><http.ruta>` (por defecto `:8000/`). Esto no se
automatiza desde PC2.

### Ráfaga: puerto destino

Si en PC1 no hay nada escuchando en `rafagas.puerto_destino` (8080), las conexiones se verán como
"rechazadas" (o "errores" si el firewall de PC1 las descarta), lo cual igualmente genera tráfico
capturable. Para conexiones completas se puede levantar en PC1 `python -m http.server 8080`.

## Registro de escenarios

Cada escenario terminado correctamente se agrega a `registros/escenarios_ejecutados.csv`
(ruta configurable en `registro.ruta_csv`, relativa a la carpeta de `configuracion.yaml`).
Columnas:

| Columna | Contenido |
|---|---|
| `fecha_hora_inicio` / `fecha_hora_fin` | Hora local de PC2, `AAAA-MM-DD HH:MM:SS` |
| `tipo_escenario` | `trafico_normal_ping`, `trafico_normal_http`, `escaneo_puertos`, `rafaga_conexiones` |
| `parametros` | JSON con los parámetros usados y un resumen del resultado |
| `ip_destino` | IP de PC1 usada |

Para correlacionar con PC1, conviene que ambos equipos tengan la hora sincronizada.
La carpeta `registros/` está ignorada por git.

## Pruebas

```
cd PC2
python -m pytest
```

Las pruebas no usan la red: validan la IP destino (vacía, inválida, pública, especial y válida),
los límites de la ráfaga (incluida una ráfaga simulada que se corta al máximo), el armado del
comando nmap y la escritura del CSV.

## Estructura

```
PC2/
├── configuracion.yaml
├── menu.py                     # punto de entrada
├── requirements.txt
├── pytest.ini
├── registros/                  # CSV generado (ignorado por git)
├── src/generador_trafico/
│   ├── configuracion.py        # carga del YAML y validaciones de seguridad
│   ├── trafico_normal.py       # ping y descarga HTTP
│   ├── escaneo_puertos.py      # wrapper de nmap
│   ├── rafagas.py              # conexiones TCP con límite de duración
│   └── registrador.py          # CSV de escenarios
└── pruebas/prueba_configuracion.py
```
