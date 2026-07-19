# registro de eventos de seguridad (rs-5)
#
# escribe en un archivo de log los eventos relevantes de la sesion como
# inicios de sesion, escaneos y errores, para tener trazabilidad y auditoria.

import os
from datetime import datetime

# el log se guarda en una carpeta logs dentro del directorio del proyecto
DIR_LOGS = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs"
)
ARCHIVO_LOG = os.path.join(DIR_LOGS, "toolkit.log")


def _asegurar_directorio():
    os.makedirs(DIR_LOGS, exist_ok=True)


def registrar(nivel, mensaje):
    # agrega una linea al log con fecha, nivel y mensaje
    _asegurar_directorio()
    marca = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    linea = "[%s] [%s] %s\n" % (marca, nivel, mensaje)
    try:
        with open(ARCHIVO_LOG, "a", encoding="utf-8") as archivo:
            archivo.write(linea)
    except OSError:
        # si no se puede escribir el log no se interrumpe la ejecucion (rs-7)
        pass
