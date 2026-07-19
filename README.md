# G1_CY703_MN_Toolkit

Toolkit preliminar de seguridad para ONGs. Analiza headers y configuracion web,
resuelve DNS y escanea puertos, y genera un reporte en PDF.

## Requisitos

- Python 3.8 o superior
- Conexion a internet para analizar los objetivos

## Entorno virtual

Desde el directorio del proyecto, crear y activar un entorno virtual:

```
python -m venv .venv
source .venv/bin/activate
```

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
|------------|---------------|----------|---------------------------------------|
| `admin`    | `password`    | admin    | acceso total (incluye exportar PDF)   |
| `analista` | `analista123` | analista | análisis y reporte, sin exportar PDF  |

Las contraseñas se almacenan como salt + hash PBKDF2-HMAC-SHA256 (nunca en texto
plano) y la verificación se hace en tiempo constante.

## Menu principal

1. Analisis Web: revisa headers de seguridad (presencia y valor), certificado y
   cifradores SSL/TLS y archivos expuestos de una URL.
2. Analisis de Red: resuelve DNS (directo o inverso), detecta IPs no publicas y
   escanea puertos comunes TCP y UDP de una IP o dominio.
3. Reporte: muestra en pantalla los hallazgos de la sesion.
4. Exportar PDF: guarda el reporte en la carpeta `reportes` (solo rol admin).
0. Salir.

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

## Nota

Usar la herramienta unicamente sobre sistemas en los que se cuenta con
autorizacion.
