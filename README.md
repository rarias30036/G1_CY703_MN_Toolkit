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

- Usuario: `admin`
- Clave: `password`

## Menu principal

1. Analisis Web: revisa headers de seguridad, certificado SSL/TLS y archivos
   expuestos de una URL.
2. Analisis de Red: resuelve DNS (directo o inverso) y escanea puertos comunes
   de una IP o dominio.
3. Reporte: muestra en pantalla los hallazgos de la sesion.
4. Exportar PDF: guarda el reporte en la carpeta `reportes`.
0. Salir.

## Salidas

- Reportes PDF: se guardan en la carpeta `reportes` (se crea automaticamente).
- Registro de eventos: se guarda en `logs/toolkit.log`.

## Nota

Usar la herramienta unicamente sobre sistemas en los que se cuenta con
autorizacion.
