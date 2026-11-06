# cortex9-heartbleed-heartbeat-bounds-model

Modelo offline del chequeo de límites que faltaba en el manejador de
heartbeat de OpenSSL (CVE-2014-0160, "Heartbleed"). Cubre
`tls1_process_heartbeat()` y `dtls1_process_heartbeat()` antes y después
del commit 96db9023 (1.0.1g).

**No hay TLS.** El modelo no abre sockets ni enlaza OpenSSL, y no lee
memoria real. Un "registro" es un `bytes` de Python que representa
`rrec.data[0 .. rrec.length)`. Lo que viene detrás es una región simulada:
cada byte es sintético y lleva la etiqueta `origin="simulated"`. El modelo
cuenta cuántos de esos bytes terminarían en la respuesta.

## Resultados

El barrido tiene 5.590 registros por versión e implementación:

- **1.0.1f:** 3.551 registros filtran bytes simulados, 8.972.661 bytes en
  total y un máximo de 65.535 por respuesta.
- **1.0.1g:** 0 registros filtran.

Con registros válidos (`rrec.length <= 16384`), el chequeo DTLS de
`write_length` es redundante una vez pasado el chequeo de longitud.

Para el detalle, el uso y las fuentes, consulta README.md, SOURCES.md,
LIMITATIONS.md y PRACTICE.md.

Licencia: Apache-2.0.
