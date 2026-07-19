# analisis de headers de seguridad http
#
# hace una peticion a la pagina y revisa si estan presentes los headers de
# seguridad mas importantes. genera un hallazgo por cada header ausente y
# tambien detecta la divulgacion de tecnologia del servidor.

import re

import requests

from common import findings as F
from common import logger

# max-age minimo recomendado para hsts (1 anio en segundos)
_HSTS_MAX_AGE_MINIMO = 31536000

# se identifica la herramienta en el user-agent de las peticiones
CABECERAS = {"User-Agent": "G1-CY703-Toolkit"}

# headers de seguridad esperados con su severidad, motivo y recomendacion
HEADERS_ESPERADOS = [
    {
        "nombre": "strict-transport-security",
        "sev": "ALTA",
        "motivo": "obliga a usar https y evita el downgrade a http",
        "reco": "configurar strict-transport-security con un max-age de al menos 31536000 segundos",
    },
    {
        "nombre": "content-security-policy",
        "sev": "ALTA",
        "motivo": "mitiga ataques de inyeccion de scripts (xss)",
        "reco": "definir una politica csp restrictiva, por ejemplo default-src 'self'",
    },
    {
        "nombre": "x-frame-options",
        "sev": "MEDIA",
        "motivo": "evita que la pagina se cargue dentro de un iframe (clickjacking)",
        "reco": "configurar x-frame-options en DENY o SAMEORIGIN",
    },
    {
        "nombre": "x-content-type-options",
        "sev": "MEDIA",
        "motivo": "evita que el navegador adivine el tipo de contenido (mime sniffing)",
        "reco": "configurar x-content-type-options en nosniff",
    },
    {
        "nombre": "referrer-policy",
        "sev": "BAJA",
        "motivo": "controla que informacion de origen se comparte con otros sitios",
        "reco": "configurar referrer-policy en strict-origin-when-cross-origin",
    },
    {
        "nombre": "permissions-policy",
        "sev": "BAJA",
        "motivo": "restringe el uso de funciones del navegador como camara o microfono",
        "reco": "definir una permissions-policy restrictiva",
    },
]


def obtener_headers(url, timeout=10):
    # hace una peticion get y devuelve los headers en minuscula y el codigo http.
    # el timeout evita que la peticion se quede bloqueada (rs-8).
    try:
        respuesta = requests.get(
            url, timeout=timeout, allow_redirects=True, headers=CABECERAS, verify=True
        )
        headers = {k.lower(): v for k, v in respuesta.headers.items()}
        return headers, respuesta.status_code
    except requests.exceptions.SSLError:
        # si falla la verificacion del certificado se reintenta sin verificar
        # para no frenar la revision de headers (el problema de tls lo reporta
        # el modulo ssl_tls por separado)
        try:
            requests.packages.urllib3.disable_warnings()
            respuesta = requests.get(
                url, timeout=timeout, allow_redirects=True, headers=CABECERAS, verify=False
            )
            headers = {k.lower(): v for k, v in respuesta.headers.items()}
            return headers, respuesta.status_code
        except requests.exceptions.RequestException:
            return None, None
    except requests.exceptions.RequestException:
        return None, None


def analizar(url):
    # revisa los headers de seguridad y devuelve una lista de hallazgos
    hallazgos = []

    headers, estado = obtener_headers(url)
    if headers is None:
        print("  [-] no se pudo conectar a %s" % url)
        logger.registrar("ADVERTENCIA", "fallo la conexion web con %s" % url)
        return hallazgos

    print("  [i] respuesta http %s, revisando headers de seguridad..." % estado)

    for esperado in HEADERS_ESPERADOS:
        nombre = esperado["nombre"]
        if nombre in headers:
            print("      [ok] %s presente" % nombre)
        else:
            print("      [!] falta %s" % nombre)
            hallazgos.append(F.crear_hallazgo(
                "web",
                "header de seguridad ausente: %s" % nombre,
                esperado["sev"],
                "la respuesta no incluye el header %s. %s" % (nombre, esperado["motivo"]),
                esperado["reco"],
                identificador="WEB-HDR",
            ))

    # divulgacion de la tecnologia del servidor
    if "x-powered-by" in headers:
        hallazgos.append(F.crear_hallazgo(
            "web",
            "el servidor divulga su tecnologia (x-powered-by)",
            "INFO",
            "el header x-powered-by expone la tecnologia del servidor: %s" % headers["x-powered-by"],
            "eliminar el header x-powered-by en la configuracion del servidor",
            identificador="WEB-HDR",
            evidencia={"x-powered-by": headers["x-powered-by"]},
        ))

    # analisis del valor de los headers presentes
    hallazgos.extend(_analizar_valores(headers))
    return hallazgos


def _analizar_valores(headers):
    # revisa que los headers de seguridad presentes tengan un valor solido
    hallazgos = []

    # hsts con un max-age demasiado corto
    hsts = headers.get("strict-transport-security", "")
    if hsts:
        m = re.search(r"max-age\s*=\s*(\d+)", hsts.lower())
        max_age = int(m.group(1)) if m else 0
        if max_age < _HSTS_MAX_AGE_MINIMO:
            print("      [!] hsts con max-age bajo (%d s)" % max_age)
            hallazgos.append(F.crear_hallazgo(
                "web",
                "hsts con max-age demasiado corto",
                "MEDIA",
                "el header strict-transport-security tiene un max-age de %d segundos, "
                "menor al minimo recomendado de %d" % (max_age, _HSTS_MAX_AGE_MINIMO),
                "configurar hsts con un max-age de al menos 31536000 segundos (1 anio)",
                identificador="WEB-HDR",
                evidencia={"strict-transport-security": hsts},
            ))

    # csp permisiva con unsafe-inline o unsafe-eval
    csp = headers.get("content-security-policy", "").lower()
    if csp and ("unsafe-inline" in csp or "unsafe-eval" in csp):
        print("      [!] csp permisiva (unsafe-inline/unsafe-eval)")
        hallazgos.append(F.crear_hallazgo(
            "web",
            "content-security-policy permisiva",
            "MEDIA",
            "la politica csp usa unsafe-inline o unsafe-eval, lo que debilita la "
            "proteccion contra inyeccion de scripts (xss)",
            "eliminar unsafe-inline y unsafe-eval de la politica csp",
            identificador="WEB-HDR",
            evidencia={"content-security-policy": headers.get("content-security-policy", "")},
        ))

    return hallazgos
