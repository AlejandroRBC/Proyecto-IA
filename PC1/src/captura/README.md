# Módulo `captura`

- `flujos.py`: agrupa paquetes en flujos bidireccionales y calcula las 10 características
  del modelo con las convenciones de CICFlowMeter. No depende de scapy ni de la red.
- `capturador.py`: captura con scapy (Npcap), evalúa los flujos cerrados con el detector
  y escribe los CSV de `datos/en_vivo/` y el estado que lee el panel.

Se ejecuta con `python scripts/capturar_en_vivo.py`. Ver la sección
"Captura en vivo" del README de PC1.
