# G1_CY703_MN_Toolkit

Toolkit de seguridad para ONGs. Analiza headers y configuracion web,
resuelve DNS y escanea puertos, y genera un reporte en PDF.

## Requisitos

- Python 3.8 o superior
- Conexion a internet para analizar los objetivos (no se requiere para
  correr la suite de pruebas unitarias)

## Entorno virtual

Desde el directorio del proyecto, crear y activar un entorno virtual:

```
python -m venv .venv
source .venv/bin/activate
```

En Windows, activar con `.venv\Scripts\activate`.

## Instalacion

Con el entorno virtual activo, instalar las dependencias:

```
python install.py
```

Esto instala las librerias listadas en `requirements.txt` (requests y reportlab).

## Ejecucion

```
python run.py
```

Al iniciar se muestra el aviso legal (escribir `acepto` para continuar) y luego
el inicio de sesion.

Credenciales del prototipo:

| Usuario    | Clave         | Rol      | Permisos                              |
|------------|---------------|----------|----------------------------------------|
| `admin`    | `password`    | admin    | acceso total (incluye exportar PDF)   |
| `analista` | `analista123` | analista | analisis y reporte, sin exportar PDF  |

Las contraseñas se almacenan como salt + hash PBKDF2-HMAC-SHA256 (nunca en texto
plano) y la verificacion se hace en tiempo constante. Se permite un maximo de
3 intentos de inicio de sesion antes de cerrar la aplicacion.

## Menu principal

```
1. Analisis Web       headers, ssl/tls y archivos expuestos
2. Analisis de Red    resuelve dns y escanea puertos comunes
3. Reporte            muestra los hallazgos de esta sesion
4. Exportar PDF       guarda el reporte en la carpeta reportes
0. Salir
```

1. **Analisis Web**: revisa headers de seguridad (presencia y valor), certificado y
   cifradores SSL/TLS y archivos expuestos de una URL.
2. **Analisis de Red**: resuelve DNS (directo o inverso), detecta IPs no publicas,
   dominios sospechosos y escanea puertos comunes TCP y UDP de una IP o dominio.
3. **Reporte**: muestra en pantalla los hallazgos de la sesion, ordenados por
   severidad, junto con un puntaje de riesgo de 0 a 100.
4. **Exportar PDF**: guarda el reporte en la carpeta `reportes` (solo rol admin).
0. **Salir**: finaliza la ejecucion.

El menu y las acciones se restringen segun el rol autenticado (autorizacion por
roles, principio de minimo privilegio).

## Salidas

- Reportes PDF: se guardan en la carpeta `reportes` (se crea automaticamente).
- Registro de eventos: se guarda en `logs/toolkit.log`.

## Pruebas

Las pruebas unitarias (pytest) estan en la carpeta `tests`. Para ejecutarlas:

```
pip install -r tests/requirements-dev.txt
python -m pytest
```

No requieren conexion a internet. En `tests/README.md` se detalla la cobertura
por archivo y su relacion con los requerimientos de seguridad.

## Arquitectura y estructura del proyecto

Arquitectura modular monolitica en CLI, sin exponer puertos de entrada ni
depender de un servidor. Flujo de ejecucion:

```
run.py -> main.py (aviso legal, login, menu)
       -> web_module/scanner.py  o  network_module/scanner.py
       -> modulos especializados de analisis
       -> common/findings.py (consolidacion)
       -> common/report.py (reporte en pantalla o PDF)
```

```
G1_CY703_MN_Toolkit/
├── run.py                     lanzador, agrega el proyecto al sys.path
├── main.py                    aviso legal, login, menu principal
├── install.py                 instala las dependencias de requirements.txt
├── common/
│   ├── auth.py                autenticacion, roles y hashing de contraseñas
│   ├── validators.py          validacion y normalizacion de entradas
│   ├── logger.py              registro de eventos en logs/toolkit.log
│   ├── findings.py            esquema comun de hallazgos y puntaje de riesgo
│   └── report.py              generacion del reporte en PDF
├── web_module/
│   ├── scanner.py              orquesta el analisis web
│   ├── headers.py               headers de seguridad HTTP
│   ├── ssl_tls.py                certificado, TLS y cifradores debiles
│   └── exposed_files.py          rutas y archivos sensibles expuestos
├── network_module/
│   ├── scanner.py               orquesta el analisis de red
│   ├── dns_analysis.py           resolucion DNS directa/inversa
│   └── port_scanner.py           escaneo de puertos TCP y UDP
└── tests/                     suite de pruebas unitarias (pytest)
```

## Documentacion tecnica: modulos y requerimientos de seguridad

Cada modulo tiene una responsabilidad unica y se comunica con los demas
unicamente a traves del esquema comun de hallazgos, lo que reduce el
acoplamiento entre componentes.

| Requerimiento | Descripcion | Modulo(s) principal(es) |
|---|---|---|
| RS-1 | Autenticacion de usuarios | `common/auth.py` |
| RS-2 | Limite de intentos en la autenticacion (`MAX_INTENTOS = 3`) | `common/auth.py` |
| RS-3 | Autorizacion basada en roles (`PERMISOS`) | `common/auth.py`, `main.py` |
| RS-4 | Gestion de contraseñas (PBKDF2-HMAC-SHA256, salt por usuario, verificacion en tiempo constante) | `common/auth.py` |
| RS-5 | Registro de eventos de seguridad | `common/logger.py` |
| RS-6 | Validacion de entradas por lista blanca (IP, dominio, URL) | `common/validators.py` |
| RS-7 | Manejo de excepciones especificas sin exponer detalles internos | `web_module/scanner.py`, `network_module/scanner.py`, `common/logger.py` |
| RS-8 | Tiempos de espera explicitos en toda conexion de red | `web_module/headers.py`, `web_module/ssl_tls.py`, `network_module/port_scanner.py` |
| RS-9 | Encapsulamiento y separacion de modulos | estructura general del repositorio |
| RS-10 | Aviso legal antes de cualquier analisis | `main.py` |

### Decisiones de seguridad relevantes

- PBKDF2-HMAC-SHA256 con 200,000 iteraciones y salt unico por usuario para las
  contraseñas.
- Validacion de entradas por lista blanca (se acepta solo lo que coincide con
  un patron conocido) en lugar de lista negra.
- Captura de excepciones especificas (por ejemplo `socket.gaierror`,
  `requests.exceptions.SSLError`) en lugar de excepciones genericas.
- Timeouts explicitos en toda operacion de red para evitar bloqueos
  indefinidos.
- Arquitectura CLI en lugar de una aplicacion web, evitando la superficie de
  ataque adicional que introduciria un servidor expuesto.

### Limitaciones conocidas

- El escaneo de puertos (`network_module/port_scanner.py`) crea los sockets
  con `socket.AF_INET`, por lo que actualmente solo soporta objetivos IPv4.
  Un objetivo IPv6 pasa la validacion de entradas y la resolucion DNS
  correctamente, pero el escaneo de puertos falla de forma controlada (RS-7).
- Las credenciales del prototipo estan definidas de forma fija en
  `common/auth.py`. Para un entorno de uso real se recomienda migrarlas a un
  mecanismo externo (variables de entorno o configuracion fuera del control
  de versiones).

## Nota

Usar la herramienta unicamente sobre sistemas en los que se cuenta con
autorizacion.
