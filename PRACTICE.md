# Guía práctica / Practice guide

Ejercicios **offline** con registros construidos en memoria. No hay TLS,
red ni memoria real. *English summary at the end.*

## Comandos locales

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m heartbeat_model check --length-field 5 --body-len 21
python3 scripts/gen_results.py /tmp/out && diff -r results /tmp/out
```

## Ejercicios graduados

**Nivel 1: registro normal.** Con el tipo 1, un campo de longitud de 5 y un
cuerpo de 21 bytes, calcula `rrec.length` y la longitud de la respuesta.
Comprobación: `rrec_length` = 24 y `response_length` = 24 en ambas
versiones.

**Nivel 2: el caso clásico.** Usa `--length-field 65535 --body-len 0`.
¿Cuántos bytes simulados se ecoan en 1.0.1f?
Comprobación: `echoed_simulated` = 65535; 1.0.1g responde `DISCARD`.

**Nivel 3: fórmula cerrada.** Deduce a mano la fuga en 1.0.1f para
`rrec.length >= 3`.
Comprobación: `max(0, payload - (rrec.length - 3))`, que coincide con
`test_closed_form_leak_pre`.

**Nivel 4: frontera mínima.** ¿Por qué un registro de 19 bytes con un
payload de 0 se acepta en 1.0.1g?
Comprobación: `1+2+0+16 > 19` es falso; el caso `min-valid` da `RESPOND`.

**Nivel 5: eco del propio padding.** Usa el campo 2 con un cuerpo de 17
(`rrec.length` 20). ¿Hay fuga en 1.0.1f? ¿Qué hace 1.0.1g?
Comprobación: la fuga es 0 (se ecoan bytes del propio registro), y 1.0.1g
da `DISCARD`.

**Nivel 6: un byte de más.** Con el campo 17 y un cuerpo de 16, ¿cuál es
el primer offset simulado?
Comprobación: `first_simulated_offset` = 19 y la fuga es 1.

**Nivel 7: cabecera truncada.** En el barrido, ¿cuántos registros de 1.0.1f
leen la cabecera fuera del registro?
Comprobación: `simulated_header_reads` = 258 en `results/sweep_summary.csv`.

**Nivel 8: chequeo DTLS redundante.** Demuestra que, tras el chequeo de
longitud, `write_length <= rrec.length`.
Comprobación: `payload <= rrec.length - 19`, por lo tanto
`3 + payload + 16 <= rrec.length`. El caso `max-record-dtls-ok` da
`RESPOND`.

## English summary

Eight levels go from a normal record to the classic 0xFFFF request, the
closed-form leak, the 19-byte boundary, echoing the record's own padding,
an off-by-one read, truncated-header reads, and the redundancy of the
DTLS write-length check. Each level has an assertion that can be checked
against `results/` or the tests.
