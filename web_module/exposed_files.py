# deteccion de archivos y rutas sensibles expuestas
#
# prueba una lista corta de rutas conocidas que no deberian ser accesibles
# de forma publica (archivos de configuracion, respaldos, repositorios, etc.)
# y reporta las que responden con codigo 200.

import uuid

import requests
from urllib.parse import urljoin

from common import findings as F

# se identifica la herramienta en el user-agent de las peticiones
CABECERAS = {"User-Agent": "G1-CY703-Toolkit"}

# rutas sensibles a probar con su severidad asociada
RUTAS_SENSIBLES = {
    ".env": "ALTA",
    ".git/config": "ALTA",
    "backup.zip": "ALTA",
    "backup.sql": "ALTA",
    "config.php.bak": "ALTA",
    "wp-config.php.bak": "ALTA",
    "phpinfo.php": "MEDIA",
    ".htaccess": "MEDIA",
    "server-status": "MEDIA",
    ".DS_Store": "BAJA",
}


def _tiene_soft_404(base):
    # pide una ruta aleatoria inexistente. si responde 200, el servidor devuelve
    # 200 a cualquier ruta (soft-404) y no se puede confiar en ese codigo.
    ruta_azar = "no-existe-%s" % uuid.uuid4().hex
    try:
        respuesta = requests.get(
            urljoin(base, ruta_azar), timeout=8, allow_redirects=False,
            headers=CABECERAS, verify=False,
        )
        return respuesta.status_code == 200
    except requests.exceptions.RequestException:
        return False


def analizar(url):
    # busca rutas sensibles accesibles y devuelve una lista de hallazgos
    hallazgos = []
    requests.packages.urllib3.disable_warnings()

    base = url if url.endswith("/") else url + "/"
    print("  [i] buscando archivos y rutas sensibles expuestas...")

    # si el servidor responde 200 a rutas inexistentes no se puede distinguir
    # un archivo real de un falso positivo, asi que se omite esta revision
    if _tiene_soft_404(base):
        print("  [i] el servidor responde 200 a rutas inexistentes (soft-404), se omite")
        return hallazgos

    for ruta, severidad in RUTAS_SENSIBLES.items():
        destino = urljoin(base, ruta)
        try:
            respuesta = requests.get(
                destino, timeout=8, allow_redirects=False, headers=CABECERAS, verify=False
            )
        except requests.exceptions.RequestException:
            continue

        if respuesta.status_code == 200 and respuesta.content:
            print("      [!] expuesto: %s (200)" % ruta)
            hallazgos.append(F.crear_hallazgo(
                "web",
                "ruta sensible accesible: %s" % ruta,
                severidad,
                "la ruta %s responde con codigo 200 y es accesible publicamente" % ruta,
                "restringir el acceso o eliminar el archivo del directorio publico del servidor",
                identificador="WEB-EXP",
                evidencia={"url": destino, "estado": respuesta.status_code},
            ))
        elif respuesta.status_code in (401, 403):
            print("      [i] protegido: %s (%s)" % (ruta, respuesta.status_code))

    return hallazgos
