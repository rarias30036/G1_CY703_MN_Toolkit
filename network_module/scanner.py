# modulo de red
#
# orquesta el analisis de red sobre un objetivo (ip o dominio): resolucion dns
# y escaneo de puertos tcp. valida la entrada antes de ejecutar los analisis y
# consolida todos los hallazgos.

from common import logger
from common import validators
from network_module import dns_analysis
from network_module import port_scanner


def analizar(entrada):
    # valida el objetivo y ejecuta los analisis de red, devolviendo la lista
    # completa de hallazgos encontrados.
    hallazgos = []

    objetivo = validators.validar_objetivo_red(entrada)
    if objetivo is None:
        print("  [-] la entrada no es una ip ni un dominio valido")
        return hallazgos

    logger.registrar("INFO", "inicio de analisis de red sobre %s" % objetivo)

    try:
        es_ip = validators.es_ip(objetivo)
        hallazgos_dns, ip = dns_analysis.analizar(objetivo, es_ip)
        hallazgos.extend(hallazgos_dns)
        if ip:
            hallazgos.extend(port_scanner.analizar(ip))
    except Exception as error:
        # manejo de errores para que una falla no detenga el toolkit (rs-7)
        print("  [-] ocurrio un error durante el analisis de red")
        logger.registrar("ERROR", "error en analisis de red sobre %s: %s" % (objetivo, error))

    logger.registrar(
        "INFO", "fin de analisis de red sobre %s, %d hallazgos" % (objetivo, len(hallazgos))
    )
    return hallazgos
