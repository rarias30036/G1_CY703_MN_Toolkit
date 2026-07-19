# pruebas del toolkit

pruebas unitarias con pytest que verifican los requerimientos de seguridad del
proyecto. no requieren conexion a internet: las funciones de red se prueban
contra loopback (127.0.0.1) y las entradas se cubren con casos controlados.

## instalacion

```
pip install -r tests/requirements-dev.txt
```

## ejecucion

desde el directorio raiz del proyecto:

```
python -m pytest
```

## cobertura por archivo

| archivo               | requerimientos       | que verifica                                        |
|-----------------------|----------------------|-----------------------------------------------------|
| test_auth.py          | rs-1, rs-2, rs-3, rs-4 | login, limite de intentos, roles y hashing salteado |
| test_validators.py    | rs-6                 | validacion y normalizacion de entradas              |
| test_findings.py      | -                    | esquema de hallazgos, puntaje y priorizacion        |
| test_logger.py        | rs-5, rs-7           | registro de eventos y manejo de errores             |
| test_port_scanner.py  | rs-8                 | escaneo de puertos tcp/udp con tiempos de espera    |
| test_dns_analysis.py  | -                    | deteccion de dominios e ips sospechosas             |
| test_web_module.py    | -                    | analisis de headers, ssl/tls y cifradores           |
