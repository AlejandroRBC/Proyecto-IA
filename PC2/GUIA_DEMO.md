# Guía para probar la demo PC1 ↔ PC2

Esta guía explica qué datos completar y en qué orden hacer la demo entre las dos máquinas.
PC2 genera tráfico **solo hacia PC1** y anota en un CSV cuándo lo hizo.

> **Qué se puede mostrar hoy:** PC2 genera tráfico real hacia PC1 y deja constancia de
> cada escenario; PC1 lo captura en vivo (`scripts/capturar_en_vivo.py`), lo convierte en
> flujos, lo evalúa con el modelo y el panel Streamlit lo muestra en la sección
> **Monitoreo en vivo**. Ojo: el modelo se entrenó con CICIDS2017, así que no se espera
> que marque la ráfaga ni el escaneo como anómalos (ver README de PC1).
>
> IPs actuales del laboratorio: **PC1 = 192.168.1.7**, **PC2 = 192.168.1.10** (pueden cambiar).

---

## 1. Datos que hay que poner

Solo hay **un dato obligatorio**: la IP de PC1. El resto ya tiene valores por defecto que
sirven para la demo.

### 1.1 Obtener la IP de PC1 (en PC1)

```
ipconfig
```

Busca el adaptador conectado a la red del laboratorio (Wi-Fi o Ethernet) y copia la
**Dirección IPv4**, por ejemplo `192.168.1.7`. Debe empezar por `192.168.`, `10.` o
`172.16.`–`172.31.`; si es una IP pública, PC2 la rechazará.

### 1.2 Completar `PC2/configuracion.yaml` (en PC2)

| Campo | Qué poner | ¿Obligatorio? |
|---|---|---|
| `red.ip_destino_pc1` | La IPv4 de PC1 entre comillas, ej. `"192.168.1.7"` | **Sí** |
| `ping.cantidad` | Ecos de ping. `10` está bien | No |
| `ping.intervalo_segundos` | Segundos entre pings. `1` | No |
| `http.puerto` | Puerto del servidor HTTP de PC1. `8000` | No |
| `http.ruta` | Archivo a descargar, ej. `"/prueba.txt"` (o `"/"` para el listado) | No |
| `escaneo_puertos.puerto_inicial` / `puerto_final` | `1` y `1024` | No |
| `escaneo_puertos.argumentos_nmap` | `"-sT"` (añadir `-T4` para que sea más rápido: `"-sT -T4"`) | No |
| `rafagas.duracion_maxima_segundos` | `30` (máximo permitido: 60) | No |
| `rafagas.conexiones_por_segundo` | `20` | No |
| `rafagas.puerto_destino` | `8080` | No |

Ejemplo de lo único que hay que cambiar:

```yaml
red:
  ip_destino_pc1: "192.168.1.7"
```

> Recomendación: no subir a git la IP del laboratorio. Si ya está puesta, se puede usar
> una copia: `python menu.py --config mi_configuracion.yaml`.

---

## 2. Preparar PC1

1. **Misma red:** PC1 y PC2 conectados a la misma red del laboratorio.
2. **Perfil de red "Privada"** en Windows (Configuración → Red e Internet → propiedades de
   la red). Con perfil "Pública" el firewall bloquea casi todo.
3. **Permitir el ping** (el firewall de Windows lo bloquea por defecto). En PowerShell
   **como administrador**:
   ```
   New-NetFirewallRule -DisplayName "Demo PC2 - ping" -Protocol ICMPv4 -IcmpType 8 -Direction Inbound -Action Allow
   ```
4. **Levantar los servidores HTTP** (dos terminales, en una carpeta con un archivo de prueba):
   ```
   echo hola desde PC1 > prueba.txt
   python -m http.server 8000
   ```
   ```
   python -m http.server 8080
   ```
   La primera vez Windows pregunta si se permite Python en la red: aceptar en **redes privadas**.
   - El de `8000` sirve para la descarga HTTP (escenario 1).
   - El de `8080` hace que las conexiones de la ráfaga se completen (escenario 3). Sin él
     la ráfaga también funciona, pero las conexiones salen como "rechazadas" o "errores".
5. **(Opcional) Otra forma de ver el tráfico llegar:** abrir Wireshark con el filtro
   `ip.src == <IP de PC2>`, o el Monitor de recursos → Red → Conexiones TCP.
6. **Captura en vivo y panel** (dos terminales más, desde `PC1/`). Primero comprobar que
   `captura.ip_pc2` en `PC1/configuracion.yaml` es la IP actual de PC2 (`ipconfig` en PC2),
   o pasarla con `--ip-pc2`:
   ```
   python scripts/capturar_en_vivo.py
   ```
   ```
   streamlit run src/app/panel.py
   ```
   El panel debe mostrar "Captura activa" en la sección **Monitoreo en vivo**. Si la
   captura falla por permisos, abrir esa terminal como administrador.
7. **Hora sincronizada:** comprobar que PC1 y PC2 tienen la misma hora (al minuto).
   Si no, en ambos y como administrador: `w32tm /resync`.

Para saber la IP de PC2 (útil para el filtro de Wireshark): `ipconfig` en PC2.

---

## 3. Preparar PC2

1. Instalar dependencias:
   ```
   cd PC2
   pip install -r requirements.txt
   ```
2. **Instalar nmap** desde <https://nmap.org/download.html> (instalador de Windows, opciones
   por defecto). Cerrar y abrir la terminal y comprobar:
   ```
   nmap --version
   ```
3. Completar `red.ip_destino_pc1` (sección 1.2).
4. Comprobar que PC1 responde:
   ```
   ping <IP de PC1>
   ```
5. Correr las pruebas (no usan la red):
   ```
   python -m pytest
   ```
   Deben pasar todas.

---

## 4. Guion de la demo (en PC2)

```
cd PC2
python menu.py
```

| Paso | Opción | Qué responder | Qué debe verse |
|---|---|---|---|
| 1 | `1` Tráfico normal | `s` a la descarga HTTP | `Ping 1/10 ... respuesta` (10 veces) y `Descarga HTTP ...: estado 200`. En PC1 la terminal del puerto 8000 muestra `"GET /prueba.txt HTTP/1.1" 200` |
| 2 | `2` Escaneo de puertos | `s` a la confirmación de la IP | Comando `nmap -sT -p 1-1024 <IP>`, puertos abiertos (al menos `8000/tcp` y `8080/tcp`) y `Nmap done`. Tarda de unos segundos a ~1 minuto |
| 3 | `3` Ráfaga | Duración: `10` (o Enter = 30) y `s` a la confirmación | `Ráfaga a <IP>:8080 durante 10.0 s - intentos: 200, exitosas: ...`. En PC1 la terminal del 8080 muestra muchos mensajes |
| 4 | `3` Ráfaga | Duración: `120` | Mensaje `se recorta a 30 s`: demuestra el límite de seguridad. Se puede responder `n` para cancelar |
| 5 | `4` Ver registro | — | Las filas de los pasos anteriores con hora de inicio/fin |
| 6 | `5` Salir | — | — |

Antes de los pasos 2 y 3 el programa muestra la IP destino y pide confirmar: **comprobar que
es la IP de PC1** antes de responder `s`.

### Demostrar la protección de la IP (opcional)

- Dejar `ip_destino_pc1: ""` y elegir 1, 2 o 3 → `No se ejecutó el escenario: Falta la IP de PC1`.
- Poner `ip_destino_pc1: "8.8.8.8"` → se rechaza por ser IP pública.

---

## 5. Qué entregar / guardar después de la demo

- `PC2/registros/escenarios_ejecutados.csv`: horas de inicio y fin de cada escenario. Es la
  referencia para cruzar con `PC1/datos/en_vivo/flujos_analizados.csv`.
- De PC1: `datos/en_vivo/flujos_analizados.csv`, `alertas.csv` y `flujos_capturados.csv`
  (este último tiene las características de cada flujo y servirá para un modelo del laboratorio).
- Capturas de pantalla de la terminal de PC2 y de las terminales `http.server` de PC1.

---

## 5b. Sesión para entrenar el modelo de laboratorio

Para el modelo de laboratorio de PC1 hace falta una sesión más larga con tráfico normal:

1. PC1: `python scripts/capturar_en_vivo.py --todo-el-trafico` durante 15-20 min, con
   uso normal de PC1.
2. PC2: varias veces la opción 1; al final, las opciones 2 y 3, con unos segundos entre
   escenarios.
3. Copiar `PC2/registros/escenarios_ejecutados.csv` a PC1, como
   `PC1/datos/laboratorio/escenarios_pc2.csv`.
4. PC1: `python scripts/entrenar_modelo_laboratorio.py` (detalles en el README de PC1).

---

## 6. Problemas frecuentes

| Síntoma | Causa probable | Solución |
|---|---|---|
| `Falta la IP de PC1` | `ip_destino_pc1` vacío | Completar el YAML (sección 1.2) |
| `... es pública` | Se copió una IP pública | Usar la IPv4 de la red del laboratorio |
| Ping `sin respuesta` | Firewall de PC1 bloquea ICMP o redes distintas | Regla de la sección 2.3, perfil Privada, misma red |
| Descarga: `timed out` / `Error de red` | `http.server` no está corriendo o el firewall lo bloquea | Levantar `python -m http.server 8000` y permitir Python en redes privadas |
| `No se encontró nmap` | nmap no instalado o terminal abierta antes de instalarlo | Instalar nmap y abrir una terminal nueva |
| nmap: `Host seems down` | PC1 no responde al ping de descubrimiento | Habilitar el ping en PC1, o usar `argumentos_nmap: "-sT -Pn"` |
| Ráfaga con todo en `errores` | Firewall de PC1 descarta el puerto 8080 | Levantar el `http.server 8080` y permitirlo en el firewall |
| Ráfaga con todo en `rechazadas` | Nada escucha en 8080 en PC1 | Normal si no se levantó el servidor; igual genera tráfico |

---

## 7. Al terminar (en PC1)

- Detener los `http.server` con Ctrl+C.
- Si se creó la regla de ping y ya no se quiere (PowerShell como administrador):
  ```
  Remove-NetFirewallRule -DisplayName "Demo PC2 - ping"
  ```
