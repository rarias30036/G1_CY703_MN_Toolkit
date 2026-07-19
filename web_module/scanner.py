# modulo web
#
# orquesta los distintos analisis web sobre una url: revision de headers de
# seguridad, auditoria ssl/tls y deteccion de archivos expuestos. valida la
# entrada antes de ejecutar los analisis y consolida todos los hallazgos.

from common import logger
from common import validators
from web_module import headers
from web_module import ssl_tls
from web_module import exposed_files


def analizar(url_ingresada):
    # valida la url y ejecuta los analisis web, devolviendo la lista completa
    # de hallazgos encontrados.
    hallazgos = []

    url = validators.normalizar_url(url_ingresada)
    if url is None:
        print("  [-] la url ingresada no es valida")
        return hallazgos

    logger.registrar("INFO", "inicio de analisis web sobre %s" % url)

    try:
        hallazgos.extend(headers.analizar(url))
        hallazgos.extend(ssl_tls.analizar(url))
        hallazgos.extend(exposed_files.analizar(url))
    except Exception as error:
        # manejo de errores para que una falla en un analisis no detenga el toolkit (rs-7)
        print("  [-] ocurrio un error durante el analisis web")
        logger.registrar("ERROR", "error en analisis web sobre %s: %s" % (url, error))

    logger.registrar(
        "INFO", "fin de analisis web sobre %s, %d hallazgos" % (url, len(hallazgos))
    )
    return hallazgos
